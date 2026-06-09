#include "nest/bird.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "conf/conf.h"
#include "lib/resource.h"
#include "lib/string.h"
#include "filter/filter.h"
#include "nest/cbor_cmds.h"
#include "nest/cbor_shortcuts.h"

extern int shutting_down;
extern int configuring;
extern pool *rt_table_pool;
extern pool *rta_pool;
extern TLIST_LIST(proto) global_proto_list;

static inline int64_t
cbor_btime(btime t)
{
  return current_real_time() - (current_time() - t);
}

static int
cbor_arg_is(struct argument *arg, const char *str)
{
  uint len = strlen(str);
  return (arg->len == len) && !memcmp(arg->arg, str, len);
}

static int
cbor_arg_matches(struct argument *arg, const char *str)
{
  uint len = strlen(str);
  return (arg->len == len) && !memcmp(arg->arg, str, len);
}

static const char *
cbor_proto_state_name(struct proto *p)
{
  switch (p->proto_state)
  {
  case PS_DOWN_XX:	return "down";
  case PS_START:	return "start";
  case PS_UP:		return "up";
  case PS_STOP:		return "stop";
  case PS_FLUSH:	return "flush";
  default:		return "unknown";
  }
}

static const char *
cbor_channel_state_name(struct channel *c)
{
  switch (c->channel_state)
  {
  case CS_DOWN:		return "down";
  case CS_START:	return "start";
  case CS_UP:		return "up";
  case CS_STOP:		return "stop";
  case CS_PAUSE:	return "pause";
  default:		return "unknown";
  }
}

static const char *
cbor_limit_action_name(uint action)
{
  switch (action)
  {
  case PLA_NONE:	return "none";
  case PLA_WARN:	return "warn";
  case PLA_BLOCK:	return "block";
  case PLA_RESTART:	return "restart";
  case PLA_DISABLE:	return "disable";
  default:		return "unknown";
  }
}

static int
cbor_symbol_type(struct argument *arg)
{
  if (cbor_arg_is(arg, "table"))
    return SYM_TABLE;
  if (cbor_arg_is(arg, "filter"))
    return SYM_FILTER;
  if (cbor_arg_is(arg, "function"))
    return SYM_FUNCTION;
  if (cbor_arg_is(arg, "protocol"))
    return SYM_PROTO;
  if (cbor_arg_is(arg, "template"))
    return SYM_TEMPLATE;
  if (cbor_arg_is(arg, "constant"))
    return SYM_CONSTANT;
  if (cbor_arg_is(arg, "variable"))
    return SYM_VARIABLE;

  return -1;
}

static void
cbor_memory_item(struct cbor_writer *w, const char *name, struct resmem mem)
{
  cbor_add_string(w, name);
  cbor_open_block_with_length(w, 2);
  cbor_string_uint(w, "effective", mem.effective);
  cbor_string_uint(w, "overhead", mem.overhead);
}

uint
cmd_show_memory_cbor(byte *tbuf, uint capacity, struct linpool *lp)
{
  struct cbor_writer *w = cbor_init(tbuf, capacity, lp);
  cbor_open_block_with_length(w, 1);
  cbor_add_string(w, "show_memory:message");
  cbor_open_block_with_length(w, 2);
  cbor_string_string(w, "header", "BIRD memory usage");
  cbor_add_string(w, "body");
  cbor_open_block(w);
  cbor_memory_item(w, "routing_tables", rmemsize(rt_table_pool));
  cbor_memory_item(w, "route_attributes", rmemsize(rta_pool));
  cbor_memory_item(w, "protocols", rmemsize(proto_pool));
  cbor_memory_item(w, "current_config", rmemsize(config_pool));

  struct resmem total = rmemsize(&root_pool);
#ifdef HAVE_MMAP
  uint hot_pages = atomic_load_explicit(&pages_kept, memory_order_relaxed)
		+ atomic_load_explicit(&pages_kept_locally, memory_order_relaxed);
  uint cold_pages_index = atomic_load_explicit(&pages_kept_cold_index, memory_order_relaxed);
  struct resmem standby = { .overhead = page_size * (hot_pages + cold_pages_index) };
  cbor_memory_item(w, "standby_memory", standby);
  total.overhead += standby.overhead;
#endif
  cbor_memory_item(w, "total", total);
  cbor_close_block_or_list(w);
  return w->pt;
}

uint
cmd_show_status_cbor(byte *tbuf, uint capacity, struct linpool *lp)
{
  struct cbor_writer *w = cbor_init(tbuf, capacity, lp);
  cbor_open_block_with_length(w, 1);
  cbor_add_string(w, "show_status:message");
  cbor_open_block_with_length(w, 3);

  rcu_read_lock();
  struct global_runtime *gr = atomic_load_explicit(&global_runtime, memory_order_acquire);
  cbor_string_string(w, "version", BIRD_VERSION);
  cbor_add_string(w, "body");
  cbor_open_block_with_length(w, 5);
  cbor_string_ipv4(w, "router_id", gr->router_id);
  cbor_string_string(w, "hostname", gr->hostname ?: "");
  cbor_string_epoch_time(w, "server_time", cbor_btime(current_time()), -6);
  cbor_string_epoch_time(w, "last_reboot", cbor_btime(boot_time), -6);
  cbor_string_epoch_time(w, "last_reconfiguration", cbor_btime(gr->load_time), -6);
  rcu_read_unlock();

  cbor_add_string(w, "state");
  switch (config_status())
  {
  case CONF_SHUTDOWN:
    cbor_add_string(w, "Shutdown in progress");
    break;
  case CONF_PROGRESS:
  case CONF_QUEUED:
    cbor_add_string(w, "Reconfiguration in progress");
    break;
  default:
    cbor_add_string(w, "Daemon is up and running");
    break;
  }

  return w->pt;
}

static void
cbor_symbol_item(struct cbor_writer *w, struct symbol *sym)
{
  cbor_open_block_with_length(w, 2);
  cbor_string_string(w, "name", sym->name);
  cbor_string_string(w, "type", cf_symbol_class_name(sym));
}

uint
cmd_show_symbols_cbor(byte *tbuf, uint capacity, struct arg_list *args, struct linpool *lp)
{
  struct cbor_writer *w = cbor_init(tbuf, capacity, lp);
  cbor_open_block_with_length(w, 1);
  cbor_add_string(w, "show_symbols:message");
  cbor_open_block_with_length(w, 1);
  cbor_add_string(w, "table");
  cbor_open_list(w);

  struct config *cfg = OBSREF_GET(config);
  if (!cfg)
  {
    cbor_close_block_or_list(w);
    return w->pt;
  }

  int show_type = SYM_VOID;
  int name_arg = -1;

  if (args->pt > 0)
  {
    show_type = cbor_symbol_type(&args->args[args->pt - 1]);
    if (show_type < 0)
      name_arg = args->pt - 1;
  }

  for (const struct sym_scope *scope = cfg->root_scope; scope; scope = scope->next)
    HASH_WALK(scope->hash, next, sym)
    {
      if (name_arg >= 0)
      {
	if (cbor_arg_matches(&args->args[name_arg], sym->name))
	  cbor_symbol_item(w, sym);
	continue;
      }

      if (show_type == SYM_VARIABLE)
      {
	if ((sym->class & 0xffffff00) != SYM_VARIABLE)
	  continue;
      }
      else if (show_type == SYM_CONSTANT)
      {
	if ((sym->class & 0xffffff00) != SYM_CONSTANT)
	  continue;
      }
      else if (show_type != SYM_VOID && sym->class != show_type)
	continue;

      cbor_symbol_item(w, sym);
    }
    HASH_WALK_END;

  cbor_close_block_or_list(w);
  return w->pt;
}

static void
cbor_limit(struct cbor_writer *w, const char *key, struct limit *l, int active, int action)
{
  if (!l->action)
    return;

  cbor_add_string(w, key);
  cbor_open_block_with_length(w, 3);
  cbor_string_uint(w, "limit", l->max);
  cbor_string_string(w, "action", cbor_limit_action_name(action));
  cbor_string_int(w, "hit", active ? 1 : 0);
}

static void
cbor_channel_stats(struct cbor_writer *w, struct channel *c)
{
  struct channel_import_stats *ch_is = &c->import_stats;
  struct channel_export_stats *ch_es = &c->export_stats;
  struct rt_import_stats *rt_is = c->in_req.hook ? &c->in_req.hook->stats : NULL;
  struct rt_export_stats *rt_es = &c->out_req.stats;
  struct rt_export_stats *rt_as = &c->alt_req.stats;

#define SON(ie, item)	((ie) ? (ie)->item : 0)
#define SRI(item)	SON(rt_is, item)
#define SRE(item)	SON(rt_es, item) + (c->alt_export ? SON(rt_as, item) : 0)
#define SCI(item)	(ch_is->item)
#define SCE(item)	(ch_es->item)

  cbor_add_string(w, "stats");
  cbor_open_block(w);
  u32 rx_routes = c->rx_limit.count;
  u32 in_routes = c->in_limit.count;
  u32 out_routes = c->out_limit.count;

  cbor_string_uint(w, "imported_routes", in_routes);
  if (c->in_keep)
    cbor_string_uint(w, "filtered_routes", (rx_routes >= in_routes) ? (rx_routes - in_routes) : 0);
  cbor_string_uint(w, "exported_routes", out_routes);
  cbor_string_uint(w, "preferred_routes", SRI(pref));

  cbor_add_string(w, "import_updates");
  cbor_open_list_with_length(w, 7);
  cbor_add_uint(w, SCI(updates_received));
  cbor_add_uint(w, SCI(updates_invalid));
  cbor_add_uint(w, SCI(updates_filtered));
  cbor_add_uint(w, SRI(updates_ignored));
  cbor_add_uint(w, SCI(updates_limited_rx));
  cbor_add_uint(w, SCI(updates_limited_in));
  cbor_add_uint(w, SRI(updates_accepted));

  cbor_add_string(w, "import_withdraws");
  cbor_open_list_with_length(w, 4);
  cbor_add_uint(w, SCI(withdraws_received));
  cbor_add_uint(w, SCI(withdraws_invalid));
  cbor_add_uint(w, SRI(withdraws_ignored));
  cbor_add_uint(w, SRI(withdraws_accepted));

  cbor_add_string(w, "export_updates");
  cbor_open_list_with_length(w, 6);
  cbor_add_uint(w, SRE(updates_received));
  cbor_add_uint(w, SCE(updates_rejected));
  cbor_add_uint(w, SCE(updates_filtered));
  cbor_add_uint(w, SCE(updates_ignored));
  cbor_add_uint(w, SCE(updates_limited));
  cbor_add_uint(w, SCE(updates_accepted));

  cbor_add_string(w, "export_withdraws");
  cbor_open_list_with_length(w, 3);
  cbor_add_uint(w, SRE(withdraws_received));
  cbor_add_uint(w, SCE(withdraws_ignored));
  cbor_add_uint(w, SCE(withdraws_accepted));

  cbor_close_block_or_list(w);

#undef SRI
#undef SRE
#undef SCI
#undef SCE
#undef SON
}

static void
cbor_channel_info(struct cbor_writer *w, struct channel *c)
{
  cbor_open_block(w);
  cbor_string_string(w, "name", c->name ?: "");
  cbor_string_string(w, "state", cbor_channel_state_name(c));
  cbor_string_string(w, "import_state", rt_import_state_name(rt_import_get_state(c->in_req.hook)));
  cbor_string_string(w, "export_state", rt_export_state_name(rt_export_get_state(&c->out_req)));
  if (c->alt_export)
    cbor_string_string(w, "alt_export_state", rt_export_state_name(rt_export_get_state(&c->alt_req)));
  cbor_string_string(w, "table", c->table->name);
  cbor_string_uint(w, "preference", c->preference);
  cbor_string_string(w, "input_filter", filter_name(c->in_filter));
  cbor_string_string(w, "output_filter", filter_name(c->out_filter));
  cbor_limit(w, "receive_limit", &c->rx_limit, c->limit_active & (1 << PLD_RX), c->limit_actions[PLD_RX]);
  cbor_limit(w, "import_limit", &c->in_limit, c->limit_active & (1 << PLD_IN), c->limit_actions[PLD_IN]);
  cbor_limit(w, "export_limit", &c->out_limit, c->limit_active & (1 << PLD_OUT), c->limit_actions[PLD_OUT]);

  if (c->channel_state != CS_DOWN)
    cbor_channel_stats(w, c);

  cbor_close_block_or_list(w);
}

uint
cmd_show_protocols_cbor(byte *tbuf, uint capacity, struct arg_list *args, struct linpool *lp)
{
  struct cbor_writer *w = cbor_init(tbuf, capacity, lp);
  cbor_open_block_with_length(w, 1);
  cbor_add_string(w, "show_protocols:message");
  cbor_open_block_with_length(w, 1);
  cbor_add_string(w, "table");
  cbor_open_list(w);

  int all = (args->pt > 0) && cbor_arg_is(&args->args[0], "all");
  int proto_arg = (args->pt > all) ? all : -1;

  WALK_TLIST(proto, p, &global_proto_list) PROTO_LOCKED_FROM_MAIN(p)
  {
    if ((proto_arg >= 0) && !cbor_arg_matches(&args->args[proto_arg], p->name))
      continue;

    cbor_open_block(w);
    cbor_string_string(w, "name", p->name);
    cbor_string_string(w, "proto", p->proto->name);
    cbor_string_string(w, "table", p->main_channel ? p->main_channel->table->name : "---");
    cbor_string_string(w, "state", cbor_proto_state_name(p));
    cbor_string_epoch_time(w, "since", cbor_btime(p->last_state_change), -6);

    byte buf[256] = {};
    if (p->proto->get_status)
      p->proto->get_status(p, buf);
    cbor_string_string(w, "info", buf);

    if (all)
    {
      if (p->cf->dsc)
	cbor_string_string(w, "description", p->cf->dsc);
      if (p->message)
	cbor_string_string(w, "message", p->message);
      cbor_string_epoch_time(w, "created", cbor_btime(p->last_reconfiguration), -6);
      if (p->last_restart > p->last_reconfiguration)
	cbor_string_epoch_time(w, "last_autorestart", cbor_btime(p->last_restart), -6);
      if (p->cf->router_id)
	cbor_string_ipv4(w, "router_id", p->cf->router_id);
      if (p->vrf)
	cbor_string_string(w, "vrf", p->vrf->name);

      cbor_add_string(w, "channels");
      cbor_open_list(w);
      struct channel *c;
      WALK_LIST(c, p->channels)
	cbor_channel_info(w, c);
      cbor_close_block_or_list(w);
    }

    cbor_close_block_or_list(w);
  }

  cbor_close_block_or_list(w);
  return w->pt;
}

uint
cmd_show_ospf_cbor(byte *tbuf, uint capacity, struct arg_list *args UNUSED, struct linpool *lp)
{
  struct cbor_writer *w = cbor_init(tbuf, capacity, lp);
  cbor_open_block_with_length(w, 1);
  cbor_add_string(w, "show_ospf:message");
  cbor_open_block_with_length(w, 1);
  cbor_string_string(w, "not_implemented", "show ospf CBOR output is not ported to BIRD 3.3 internals yet");
  return w->pt;
}
