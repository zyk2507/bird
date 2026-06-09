/*
 *	BIRD -- YANG-CBOR / CORECONF api -- CLI model
 *
 *	(c) 2026       Maria Matejka <mq@jmq.cz>
 *	(c) 2026       CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"

#include "nest/protocol.h"
#include "nest/route.h"
#include "conf/conf.h"
#include "lib/string.h"
#include "lib/timer.h"

#include "yang/model-cli.h"
#include "lib/cbor.h"

extern pool *rt_table_pool;
extern pool *rta_pool;
extern TLIST_LIST(proto) global_proto_list;

#define YANG_MODEL_CLI_STACK_DEPTH 16
#define YANG_MODEL_CLI_PAYLOAD_MAX 65536

struct yang_model_cli_writer {
  struct cbor_writer w;
  struct cbor_writer_stack_item si[YANG_MODEL_CLI_STACK_DEPTH];
};

struct yang_model_cli_payload {
  struct coap_tx_option hdr;
  byte data[YANG_MODEL_CLI_PAYLOAD_MAX];
};

static void
yang_model_cli_writer_init(struct yang_model_cli_writer *ws, struct yang_model_cli_payload *payload)
{
  cbor_writer_init(&ws->w, YANG_MODEL_CLI_STACK_DEPTH,
      payload->hdr.data, YANG_MODEL_CLI_PAYLOAD_MAX);
}

static bool
yang_model_cli_send(struct yang_session *se, struct yang_model_cli_writer *ws,
    struct yang_model_cli_payload *payload)
{
  struct cbor_writer *w = &ws->w;

  ASSERT_DIE(cbor_writer_done(w) == 1);

  payload->hdr.len = w->data.pos - w->data.start;
  payload->hdr.type = 0;

  struct coap_tx_option *content_format = COAP_TX_OPTION_INT(
	COAP_OPT_CONTENT_FORMAT, (u8) 140);

  coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_RESP_CONTENT,
	content_format, &payload->hdr));

  return true;
}

static int64_t
yang_model_cli_btime(btime t)
{
  return current_real_time() - (current_time() - t);
}

static const char *
yang_model_cli_proto_state_name(struct proto *p)
{
  switch (p->proto_state)
  {
  case PS_DOWN_XX:	return "down";
  case PS_START:	return "start";
  case PS_UP:		return "up";
  case PS_STOP:	return "stop";
  case PS_FLUSH:	return "flush";
  default:		return "unknown";
  }
}

static const char *
yang_model_cli_config_state_name(void)
{
  switch (config_status())
  {
  case CONF_SHUTDOWN:
    return "shutdown";
  case CONF_PROGRESS:
  case CONF_QUEUED:
    return "reconfiguring";
  default:
    return "up";
  }
}

static void
cbor_putmemsize(struct cbor_writer *w, u64 offset, struct resmem m)
{
  cbor_put_posint(w, offset);
  CBOR_PUT_MAP(w) {
    cbor_put_posint(w, 1);
    cbor_put_posint(w, m.effective);
    cbor_put_posint(w, 2);
    cbor_put_posint(w, m.overhead);
  }
}

bool
yang_model_cli_rpc_call_show_memory(struct yang_session *se)
{
  struct yang_model_cli_writer ws;
  struct yang_model_cli_payload payload;
  yang_model_cli_writer_init(&ws, &payload);

  struct cbor_writer *w = &ws.w;

  CBOR_PUT_MAP(w) {
    cbor_put_posint(w, YANG_SID_CLI_SHOW_MEMORY_OUTPUT);
    CBOR_PUT_MAP(w) {
      cbor_put_posint(w, 1);
      CBOR_PUT_MAP(w) {
	struct resmem total = rmemsize(&root_pool);

	cbor_putmemsize(w, 1, rmemsize(rta_pool));
	cbor_putmemsize(w, 4, rmemsize(config_pool));
	cbor_putmemsize(w, 12, rmemsize(proto_pool));
	cbor_putmemsize(w, 15, rmemsize(rt_table_pool));

#ifdef HAVE_MMAP
	/* Pages */
	cbor_put_posint(w, 7);
	CBOR_PUT_MAP(w) {
	  uint hot_pages = atomic_load_explicit(&pages_kept, memory_order_relaxed)
	    + atomic_load_explicit(&pages_kept_locally, memory_order_relaxed);
	  uint cold_pages_index = atomic_load_explicit(&pages_kept_cold_index, memory_order_relaxed);

	  u64 hot = page_size * (hot_pages + cold_pages_index);
	  total.overhead += hot;

	  cbor_put_posint(w, 3);
	  cbor_put_posint(w, hot);

	  uint cold_pages = atomic_load_explicit(&pages_kept_cold, memory_order_relaxed);
	  uint pages_total_loc = atomic_load_explicit(&pages_total, memory_order_relaxed);
	  uint pages_active = pages_total_loc - hot_pages - cold_pages_index - cold_pages;

	  cbor_put_posint(w, 1);
	  cbor_put_posint(w, page_size * pages_active);
	  cbor_put_posint(w, 2);
	  cbor_put_posint(w, page_size * cold_pages);
	  cbor_put_posint(w, 4);
	  cbor_put_posint(w, atomic_load_explicit(&alloc_locking_in_rcu, memory_order_relaxed));
	}
#endif

	cbor_putmemsize(w, 18, total);
      }
    }
  }

  return yang_model_cli_send(se, &ws, &payload);
}

bool
yang_model_cli_rpc_call_show_status(struct yang_session *se)
{
  struct yang_model_cli_writer ws;
  struct yang_model_cli_payload payload;
  yang_model_cli_writer_init(&ws, &payload);

  struct cbor_writer *w = &ws.w;

  CBOR_PUT_MAP(w) {
    cbor_put_posint(w, YANG_SID_CLI_SHOW_STATUS_OUTPUT);
    CBOR_PUT_MAP(w) {
      cbor_put_posint(w, 1);
      CBOR_PUT_MAP(w) {
	rcu_read_lock();
	struct global_runtime *gr = atomic_load_explicit(&global_runtime, memory_order_acquire);

	char rid[IPA_MAX_TEXT_LENGTH];
	bsnprintf(rid, sizeof rid, "%R", gr->router_id);

	cbor_put_posint(w, 1);
	cbor_put_string(w, BIRD_VERSION);
	cbor_put_posint(w, 2);
	cbor_put_string(w, rid);
	cbor_put_posint(w, 3);
	cbor_put_string(w, gr->hostname ?: "");
	cbor_put_posint(w, 4);
	cbor_put_int(w, yang_model_cli_btime(current_time()));
	cbor_put_posint(w, 5);
	cbor_put_int(w, yang_model_cli_btime(boot_time));
	cbor_put_posint(w, 6);
	cbor_put_int(w, yang_model_cli_btime(gr->load_time));
	rcu_read_unlock();

	cbor_put_posint(w, 7);
	cbor_put_string(w, yang_model_cli_config_state_name());
      }
    }
  }

  return yang_model_cli_send(se, &ws, &payload);
}

static void
yang_model_cli_put_symbol(struct cbor_writer *w, struct symbol *sym)
{
  CBOR_PUT_MAP(w) {
    cbor_put_posint(w, 1);
    cbor_put_string(w, sym->name);
    cbor_put_posint(w, 2);
    cbor_put_string(w, cf_symbol_class_name(sym));
  }
}

bool
yang_model_cli_rpc_call_show_symbols(struct yang_session *se)
{
  struct yang_model_cli_writer ws;
  struct yang_model_cli_payload payload;
  yang_model_cli_writer_init(&ws, &payload);

  struct cbor_writer *w = &ws.w;

  CBOR_PUT_MAP(w) {
    cbor_put_posint(w, YANG_SID_CLI_SHOW_SYMBOLS_OUTPUT);
    CBOR_PUT_MAP(w) {
      cbor_put_posint(w, 1);
      CBOR_PUT_ARRAY(w) {
	struct config *cfg = OBSREF_GET(config);
	if (cfg)
	{
	  for (const struct sym_scope *scope = cfg->root_scope; scope; scope = scope->next)
	    HASH_WALK(scope->hash, next, sym)
	      yang_model_cli_put_symbol(w, sym);
	    HASH_WALK_END;
	}
      }
    }
  }

  return yang_model_cli_send(se, &ws, &payload);
}

static void
yang_model_cli_put_protocol(struct cbor_writer *w, struct proto *p)
{
  byte buf[256] = {};

  if (p->proto->get_status)
    p->proto->get_status(p, buf);

  CBOR_PUT_MAP(w) {
    cbor_put_posint(w, 1);
    cbor_put_string(w, p->name);
    cbor_put_posint(w, 2);
    cbor_put_string(w, p->proto->name);
    cbor_put_posint(w, 3);
    cbor_put_string(w, p->main_channel ? p->main_channel->table->name : "");
    cbor_put_posint(w, 4);
    cbor_put_string(w, yang_model_cli_proto_state_name(p));
    cbor_put_posint(w, 5);
    cbor_put_int(w, yang_model_cli_btime(p->last_state_change));
    cbor_put_posint(w, 6);
    cbor_put_string(w, buf);
  }
}

bool
yang_model_cli_rpc_call_show_protocols(struct yang_session *se)
{
  struct yang_model_cli_writer ws;
  struct yang_model_cli_payload payload;
  yang_model_cli_writer_init(&ws, &payload);

  struct cbor_writer *w = &ws.w;

  CBOR_PUT_MAP(w) {
    cbor_put_posint(w, YANG_SID_CLI_SHOW_PROTOCOLS_OUTPUT);
    CBOR_PUT_MAP(w) {
      cbor_put_posint(w, 1);
      CBOR_PUT_ARRAY(w) {
	WALK_TLIST(proto, p, &global_proto_list) PROTO_LOCKED_FROM_MAIN(p)
	  yang_model_cli_put_protocol(w, p);
      }
    }
  }

  return yang_model_cli_send(se, &ws, &payload);
}
