#include <limits.h>

#include "nest/cbor.h"
#include "nest/cbor_parse.h"
#include "nest/cbor_cmds.h"
#include "nest/cbor_shortcuts.h"

static void
skip_cbor_value(struct buff_reader *r)
{
  struct value val = get_value(r);

  switch (val.major)
  {
  case CBOR_BYTE_STR:
  case CBOR_TEXT:
    r->pt += val.val;
    return;

  case CBOR_ARRAY:
    if (val.val < 0)
    {
      while (r->pt < r->size)
      {
	uint old = r->pt;
	struct value end = get_value(r);
	if (val_is_break(end))
	  return;
	r->pt = old;
	skip_cbor_value(r);
      }
      return;
    }

    for (int i = 0; i < val.val; i++)
      skip_cbor_value(r);
    return;

  case CBOR_BLOCK:
    if (val.val < 0)
    {
      while (r->pt < r->size)
      {
	uint old = r->pt;
	struct value end = get_value(r);
	if (val_is_break(end))
	  return;
	r->pt = old;
	skip_cbor_value(r);
	skip_cbor_value(r);
      }
      return;
    }

    for (int i = 0; i < val.val; i++)
    {
      skip_cbor_value(r);
      skip_cbor_value(r);
    }
    return;

  case CBOR_TAG:
    skip_cbor_value(r);
    return;

  default:
    return;
  }
}

static uint
write_error(byte *tbuf, uint capacity, struct linpool *lp, const char *msg)
{
  struct cbor_writer *w = cbor_init(tbuf, capacity, lp);
  cbor_open_block_with_length(w, 1);
  cbor_string_string(w, "error", msg);
  return w->pt;
}

static void
append_arg(struct arg_list *args, byte *arg, uint len)
{
  if (args->pt == args->capacity)
  {
    uint new_capacity = args->capacity ? 2 * args->capacity : 4;
    struct argument *new_args = lp_alloc(args->lp, sizeof(struct argument) * new_capacity);

    if (args->args)
      memcpy(new_args, args->args, sizeof(struct argument) * args->pt);

    args->args = new_args;
    args->capacity = new_capacity;
  }

  args->args[args->pt++] = (struct argument) { .arg = arg, .len = len };
}

static struct arg_list *
parse_args(struct buff_reader *r, struct linpool *lp)
{
  struct arg_list *args = lp_allocz(lp, sizeof(struct arg_list));
  args->lp = lp;

  uint old = r->pt;
  struct value val = get_value(r);
  if (val.major != CBOR_ARRAY)
  {
    r->pt = old;
    skip_cbor_value(r);
    return args;
  }

  int indefinite = val.val < 0;
  int count = indefinite ? INT_MAX : val.val;

  for (int i = 0; i < count && r->pt < r->size; i++)
  {
    old = r->pt;
    val = get_value(r);
    if (indefinite && val_is_break(val))
      break;

    if (val.major != CBOR_BLOCK)
    {
      r->pt = old;
      skip_cbor_value(r);
      continue;
    }

    int map_indefinite = val.val < 0;
    int pairs = map_indefinite ? INT_MAX : val.val;

    for (int j = 0; j < pairs && r->pt < r->size; j++)
    {
      old = r->pt;
      val = get_value(r);
      if (map_indefinite && val_is_break(val))
	break;

      if ((val.major == CBOR_TEXT) && compare_buff_str(r, val.val, "arg"))
      {
	r->pt += val.val;
	struct value arg = get_value(r);
	if (arg.major == CBOR_TEXT)
	{
	  append_arg(args, r->buff + r->pt, arg.val);
	  r->pt += arg.val;
	}
	else
	  skip_cbor_value(r);
      }
      else
      {
	r->pt = old;
	skip_cbor_value(r);
	skip_cbor_value(r);
      }
    }
  }

  return args;
}

static uint
run_command(uint cmd, struct arg_list *args, byte *tbuf, uint capacity, struct linpool *lp)
{
  switch (cmd)
  {
  case SHOW_STATUS:
    return cmd_show_status_cbor(tbuf, capacity, lp);
  case SHOW_MEMORY:
    return cmd_show_memory_cbor(tbuf, capacity, lp);
  case SHOW_SYMBOLS:
    return cmd_show_symbols_cbor(tbuf, capacity, args, lp);
  case SHOW_OSPF:
    return cmd_show_ospf_cbor(tbuf, capacity, args, lp);
  case SHOW_PROTOCOLS:
    return cmd_show_protocols_cbor(tbuf, capacity, args, lp);
  default:
    return write_error(tbuf, capacity, lp, "unknown command");
  }
}

static uint
parse_command_payload(struct buff_reader *r, byte *tbuf, uint capacity, struct linpool *lp)
{
  struct value val = get_value(r);
  if (val.major != CBOR_BLOCK)
    return write_error(tbuf, capacity, lp, "request is not a map");

  int root_indefinite = val.val < 0;
  int root_pairs = root_indefinite ? INT_MAX : val.val;

  for (int i = 0; i < root_pairs && r->pt < r->size; i++)
  {
    uint old = r->pt;
    val = get_value(r);
    if (root_indefinite && val_is_break(val))
      break;

    if ((val.major != CBOR_TEXT) || !compare_buff_str(r, val.val, "command:do"))
    {
      r->pt = old;
      skip_cbor_value(r);
      skip_cbor_value(r);
      continue;
    }

    r->pt += val.val;
    val = get_value(r);
    if (val.major != CBOR_BLOCK)
      return write_error(tbuf, capacity, lp, "command body is not a map");

    int body_indefinite = val.val < 0;
    int body_pairs = body_indefinite ? INT_MAX : val.val;
    uint cmd = UINT_MAX;
    struct arg_list *args = lp_allocz(lp, sizeof(struct arg_list));
    args->lp = lp;

    for (int j = 0; j < body_pairs && r->pt < r->size; j++)
    {
      old = r->pt;
      val = get_value(r);
      if (body_indefinite && val_is_break(val))
	break;

      if (val.major != CBOR_TEXT)
      {
	r->pt = old;
	skip_cbor_value(r);
	skip_cbor_value(r);
	continue;
      }

      if (compare_buff_str(r, val.val, "command"))
      {
	r->pt += val.val;
	struct value cval = get_value(r);
	if (cval.major != CBOR_UINT)
	  return write_error(tbuf, capacity, lp, "command is not an integer");
	cmd = cval.val;
      }
      else if (compare_buff_str(r, val.val, "args"))
      {
	r->pt += val.val;
	args = parse_args(r, lp);
      }
      else
      {
	r->pt = old;
	skip_cbor_value(r);
	skip_cbor_value(r);
      }
    }

    if (cmd == UINT_MAX)
      return write_error(tbuf, capacity, lp, "missing command");

    return run_command(cmd, args, tbuf, capacity, lp);
  }

  return write_error(tbuf, capacity, lp, "missing command:do");
}

static int
read_framed_header(struct buff_reader *r, uint *serial_num)
{
  uint old = r->pt;
  struct value val = get_value(r);

  if ((val.major != CBOR_TAG) || (val.val != 24))
  {
    r->pt = old;
    return 0;
  }

  val = get_value(r);
  if (val.major != CBOR_BYTE_STR)
  {
    r->pt = old;
    return 0;
  }

  val = get_value(r);
  if ((val.major != CBOR_ARRAY) || (val.val != 2))
  {
    r->pt = old;
    return 0;
  }

  val = get_value(r);
  if (val.major != CBOR_UINT)
  {
    r->pt = old;
    return 0;
  }

  *serial_num = val.val;
  return 1;
}

static uint
write_framed_header(byte *tbuf, uint tbsize, struct linpool *lp, uint serial_num, uint *length_pt)
{
  struct cbor_writer *w = cbor_init(tbuf, tbsize, lp);
  cbor_add_tag(w, 24);
  *length_pt = w->pt + 1;
  cbor_write_item_with_constant_val_length_4(w, CBOR_BYTE_STR, 0);
  cbor_open_list_with_length(w, 2);
  cbor_write_item_with_constant_val_length_4(w, CBOR_UINT, serial_num);
  return w->pt;
}

uint
parse_cbor(uint size, byte *rbuf, byte *tbuf, uint tbsize, struct linpool *lp)
{
  struct buff_reader r = { .buff = rbuf, .pt = 0, .size = size };
  uint serial_num = 0;
  uint length_pt = 0;
  uint tpos = 0;
  int framed = 0;

  if (!size)
    return 0;

  framed = read_framed_header(&r, &serial_num);
  if (framed)
    tpos = write_framed_header(tbuf, tbsize, lp, serial_num, &length_pt);

  uint written = parse_command_payload(&r, tbuf + tpos, tbsize - tpos, lp);
  tpos += written;

  if (framed)
  {
    struct cbor_writer *w = cbor_init(tbuf, tbsize, lp);
    rewrite_4bytes_int(w, length_pt, tpos - (length_pt + 4));
  }

  lp_flush(lp);
  return tpos;
}

uint
detect_down(uint size UNUSED, byte *rbuf UNUSED)
{
  return 0;
}
