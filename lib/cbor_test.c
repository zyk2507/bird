/*
 *	BIRD -- CBOR Library Tests
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "lib/cbor.h"

static uint
parse_all(struct cbor_parser_context *ctx, const byte *data, uint len)
{
  uint events = 0;
  byte string_buf[256];

  for (uint i = 0; i < len; i++)
  {
    while (cbor_parse_block_end(ctx))
      events++;

    enum cbor_parse_result res = cbor_parse_byte(ctx, data[i]);
    bt_assert_msg(res != CPR_ERROR, "CBOR parse error: %s", ctx->error ?: "<none>");

    if (res == CPR_MAJOR || res == CPR_STR_END)
    {
      events++;

      if ((res == CPR_MAJOR) && ((ctx->type == CBOR_BYTES) || (ctx->type == CBOR_TEXT)))
      {
	bt_assert_msg(ctx->value < sizeof(string_buf), "String too long for test buffer");
	ctx->target_buf = string_buf;
	ctx->target_len = ctx->value;
      }
    }
  }

  while (cbor_parse_block_end(ctx))
    events++;

  return events;
}

static int
t_cbor_writer_encodes_map(void)
{
  byte buf[128];
  struct {
    struct cbor_writer w;
    struct cbor_writer_stack_item stack[8];
  } cw;

  struct cbor_writer *w = cbor_writer_init(&cw.w, 8, buf, sizeof(buf));

  CBOR_PUT_MAP(w)
  {
    cbor_put_string(w, "status");
    cbor_put_posint(w, 200);
    cbor_put_string(w, "body");
    CBOR_PUT_ARRAY(w)
    {
      cbor_put_int(w, -1);
      cbor_put_string(w, "ok");
      cbor_put_true(w);
    }
  }

  bt_assert(cbor_writer_done(w) == 1);

  static const byte expected[] = {
    0xa2,
    0x66, 's', 't', 'a', 't', 'u', 's',
    0x18, 0xc8,
    0x64, 'b', 'o', 'd', 'y',
    0x83,
    0x20,
    0x62, 'o', 'k',
    0xf5,
  };

  uint len = w->data.pos - w->data.start;
  bt_assert_msg(len == sizeof(expected), "Encoded length %u expected %u", len, (uint) sizeof(expected));
  bt_assert(!memcmp(buf, expected, sizeof(expected)));

  return 1;
}

static int
t_cbor_parser_streams_nested_data(void)
{
  static const byte data[] = {
    0xa2,
    0x61, 'a',
    0x82, 0x01, 0x02,
    0x61, 'b',
    0xa1, 0x61, 'c', 0x20,
  };

  struct cbor_parser_context *ctx = cbor_parser_new(&root_pool, 8);
  uint events = parse_all(ctx, data, sizeof(data));

  bt_assert_msg(events >= 10, "Expected parser events, got %u", events);
  bt_assert(ctx->partial_state == CPE_EXIT);

  cbor_parser_free(ctx);
  return 1;
}

static int
t_cbor_parser_finishes_root_scalar(void)
{
  static const byte data[] = { 0x18, 0x2a };

  struct cbor_parser_context *ctx = cbor_parser_new(&root_pool, 2);
  uint events = parse_all(ctx, data, sizeof(data));

  bt_assert(events == 2);
  bt_assert(ctx->type == CBOR_POSINT);
  bt_assert(ctx->value == 42);
  bt_assert(ctx->partial_state == CPE_EXIT);
  bt_assert(ctx->stack_pos == 0);

  cbor_parser_free(ctx);
  return 1;
}

static int
t_cbor_parser_reports_trailing_data(void)
{
  static const byte data[] = { 0x01, 0x02 };

  struct cbor_parser_context *ctx = cbor_parser_new(&root_pool, 2);
  enum cbor_parse_result res = cbor_parse_byte(ctx, data[0]);
  bt_assert(res == CPR_MAJOR);
  bt_assert(cbor_parse_block_end(ctx));

  res = cbor_parse_byte(ctx, data[1]);
  bt_assert(res == CPR_ERROR);
  bt_assert(ctx->error);

  cbor_parser_free(ctx);
  return 1;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_cbor_writer_encodes_map, "CBOR writer encodes nested maps and arrays");
  bt_test_suite(t_cbor_parser_streams_nested_data, "CBOR parser streams nested data");
  bt_test_suite(t_cbor_parser_finishes_root_scalar, "CBOR parser finishes root scalar values");
  bt_test_suite(t_cbor_parser_reports_trailing_data, "CBOR parser reports trailing root data");

  return bt_exit_value();
}
