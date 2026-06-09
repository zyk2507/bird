/*
 *	BIRD -- YANG-CBOR / CORECONF api
 *
 *	(c) 2026       Maria Matejka <mq@jmq.cz>
 *	(c) 2026       CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "lib/tlists.h"
#include "conf/conf.h"
#include "yang/yang.h"
#include "yang/model-cli.h"

static bool yang_default_endpoint(struct yang_session *se);

static bool
yang_send_error_once(struct yang_session *se, enum coap_msg_code code, const char *msg)
{
  if (se->error_sent)
    return true;

  struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(0, "%s", msg);
  coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, code, payload));
  se->error_sent = true;
  return true;
}

static bool
yang_model_cli_endpoint_wellknown_core(struct yang_session *se)
{
  struct yang_api *api = se->api;

  switch (se->coap.parser.state) {
    case COAP_PS_MORE:
    case COAP_PS_HEADER:
      log(L_ERR "%s: Unexpected CoAP parser state in well-known endpoint", api->name);
      return false;

    case COAP_PS_ERROR:
      log(L_ERR "%s: CoAP parser error in well-known endpoint", api->name);
      return false;

    case COAP_PS_OPTION_PARTIAL:
    case COAP_PS_OPTION_COMPLETE:
      switch (se->coap.parser.option_type) {
	case COAP_OPT_URI_QUERY:
	  /* According to RFC 6690, Sec. 4, we are not required
	   * to support filtering at the well-known path. It's desirable for later implementation tho. */
	  log(L_INFO "URI Query (%u-%u/%u): %.*s",
	      se->coap.parser.option_chunk_offset,
	      se->coap.parser.option_chunk_offset + se->coap.parser.option_chunk_len,
	      se->coap.parser.option_len,
	      se->coap.parser.option_chunk_len, se->coap.parser.option_value);
	  break;
	default:
	  if (se->coap.parser.option_type & COAP_OPT_F_CRITICAL)
	  {
	    log(L_INFO "Unhandled option %u, fail", se->coap.parser.option_type);
	    return yang_send_error_once(se, COAP_CERR_BAD_OPTION,
		tmp_sprintf("Unhandled option %u", se->coap.parser.option_type));
	  }
      }
      return true;

    case COAP_PS_PAYLOAD_COMPLETE:
      if (se->coap.parser.payload_total_len != 0)
	log(L_WARN "%s: Received GET with a payload. Weird.", api->name);

      se->endpoint = yang_default_endpoint;

      /* fall through */

    case COAP_PS_PAYLOAD_PARTIAL:
      if (!se->error_sent)
      {
	struct coap_tx_option
	  *content_format = COAP_TX_OPTION_INT(
	      COAP_OPT_CONTENT_FORMAT, (u8) 40),
	  *payload = COAP_TX_OPTION_PRINTF(0,
	      "</y>;rt=\"core.c.yl\","
	      "</c>;rt=\"core.c.ds\","
	      "</s>;rt=\"core.c.ev\"");

	coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_RESP_CONTENT,
	      content_format, payload));
      }

#if 0
      log(L_INFO "Payload (%u-%u/%u)", se->coap.parser.payload_chunk_offset,
	  se->coap.parser.payload_chunk_offset + se->coap.parser.payload_chunk_len,
	  se->coap.parser.payload_total_len);
#endif

      return true;

    default:
      bug("Unexpected CoAP parser state");

  }
}

static bool
yang_cbor_parser_error(struct yang_session *se, int pos, const char *reason)
{
  if (se->error_sent)
    return true;

  struct coap_tx_option *payload = COAP_TX_OPTION_PRINTF(
      0, "Parse error at position %u: %s", se->coap.parser.payload_chunk_offset + pos, reason);
  coap_tx_send(&se->coap, COAP_TX_RESPONSE(&se->coap, COAP_CERR_BAD_REQUEST, payload));
  se->error_sent = true;
  return true;
}

static bool
yang_push_sid(struct yang_session *se, u64 sid)
{
  u64 cur = se->sid_stack[se->sid_pos];

  /* Generate this by UYTC */
  switch (sid) {
    case YANG_SID_CLI_SHOW_MEMORY:
    case YANG_SID_CLI_SHOW_STATUS:
    case YANG_SID_CLI_SHOW_SYMBOLS:
    case YANG_SID_CLI_SHOW_PROTOCOLS:
      /* Check parent SID */
      if (cur != 0)
	return false;

      break;

    default:
      /* Unexpected SID */
      return false;
  }

  se->sid_stack[se->sid_pos + 1] = sid;
  se->sid_pos++;

  return true;
}

static bool
yang_pop_sid(struct yang_session *se)
{
  ASSERT_DIE(se->sid_pos >= 0);

  u64 cur = se->sid_stack[se->sid_pos];

  /* Generate this by UYTC
   * Only block-like items */
  switch (cur) {
    case 0:
      /* Nothing to do */
      break;

    default:
      /* Unexpected SID */
      return false;
  }

  se->sid_pos--;
  return true;
}


static bool
yang_model_cli_cbor_c(struct yang_session *se)
{
  const char *payload = se->coap.parser.payload;
  uint len = se->coap.parser.payload_chunk_len;

  for (uint i=0; i<len; i++)
  {
    while (cbor_parse_block_end(se->cbor))
      if (!yang_pop_sid(se))
	return yang_cbor_parser_error(se, i, "End of block error");

    ASSERT_DIE(se->sid_pos >= 0);

    switch (cbor_parse_byte(se->cbor, payload[i]))
    {
      case CPR_ERROR:
	return yang_cbor_parser_error(se, i, se->cbor->error);

      case CPR_MORE:
	continue;

      case CPR_MAJOR:
	switch (se->sid_state)
	{
	  case YANG_PS_RELATIVE_SID:
	    switch (se->cbor->type)
	    {
	      case CBOR_POSINT:
		if (se->sid_stack[se->sid_pos] + se->cbor->value < se->sid_stack[se->sid_pos])
		  return yang_cbor_parser_error(se, i, "SID overflow");

		if (!yang_push_sid(se, se->sid_stack[se->sid_pos] + se->cbor->value))
		  return yang_cbor_parser_error(se, i, "Unexpected SID");

		se->sid_state = YANG_PS_VALUE;
		continue;

	      case CBOR_NEGINT:
	      {
		u64 delta = se->cbor->value + 1;

		if (se->sid_stack[se->sid_pos] < delta)
		  return yang_cbor_parser_error(se, i, "SID underflow");

		if (!yang_push_sid(se, se->sid_stack[se->sid_pos] - delta))
		  return yang_cbor_parser_error(se, i, "Unexpected SID");

		se->sid_state = YANG_PS_VALUE;
		continue;
	      }

	      case CBOR_TAG:
		if (se->cbor->value == CBOR_TAG_ABSOLUTE_SID)
		{
		  se->sid_state = YANG_PS_ABSOLUTE_SID;
		  continue;
		}

		/* fall through */

	      default:
		return yang_cbor_parser_error(se, i, "Wrong SID type");
	    }

	  case YANG_PS_ABSOLUTE_SID:
	    if (se->cbor->type != CBOR_POSINT)
	      return yang_cbor_parser_error(se, i,
		  tmp_sprintf("Wrong type of absolute SID: %u", se->cbor->type));

	    if (!yang_push_sid(se, se->cbor->value))
	      return yang_cbor_parser_error(se, i, "Unexpected SID");

	    se->sid_state = YANG_PS_VALUE;
	    continue;

	    /* We kinda wanna generate this block by UYTC */
	  case YANG_PS_VALUE:
	    switch (se->sid_stack[se->sid_pos])
	    {
	      case 0:
		if (se->cbor->type != CBOR_MAP)
		  return yang_cbor_parser_error(se, i, "Wrong data for SID 0 / root");

		se->sid_state = YANG_PS_RELATIVE_SID;
		continue;

	      case YANG_SID_CLI_SHOW_MEMORY:
	      case YANG_SID_CLI_SHOW_STATUS:
	      case YANG_SID_CLI_SHOW_SYMBOLS:
	      case YANG_SID_CLI_SHOW_PROTOCOLS:
		if ((se->cbor->type != CBOR_SPECIAL) || (se->cbor->value != CBOR_SPECIAL_NULL))
		  return yang_cbor_parser_error(se, i, "Wrong RPC data; null expected");

		u64 rpc_sid = se->sid_stack[se->sid_pos];
		se->sid_pos--;
		se->sid_state = YANG_PS_RELATIVE_SID;

		switch (rpc_sid)
		{
		  case YANG_SID_CLI_SHOW_MEMORY:
		    yang_model_cli_rpc_call_show_memory(se);
		    break;
		  case YANG_SID_CLI_SHOW_STATUS:
		    yang_model_cli_rpc_call_show_status(se);
		    break;
		  case YANG_SID_CLI_SHOW_SYMBOLS:
		    yang_model_cli_rpc_call_show_symbols(se);
		    break;
		  case YANG_SID_CLI_SHOW_PROTOCOLS:
		    yang_model_cli_rpc_call_show_protocols(se);
		    break;
		}
		continue;

	      default:
		return yang_cbor_parser_error(se, i, "Unexpected SID");
	    }
	}
	bug("this shall not happen");

      case CPR_STR_END:
	return yang_cbor_parser_error(se, i, "No strings expected");
    }
  }

  while (cbor_parse_block_end(se->cbor))
    if (!yang_pop_sid(se))
      return yang_cbor_parser_error(se, len, "End of block error");

  if (se->sid_pos < 0)
    ASSERT_DIE(se->coap.parser.state == COAP_PS_PAYLOAD_COMPLETE);

  return true;
}

static bool
yang_model_cli_endpoint_c(struct yang_session *se)
{
  struct yang_api *api = se->api;

  switch (se->coap.parser.state) {
    case COAP_PS_EMPTY:
    case COAP_PS_MORE:
    case COAP_PS_HEADER:
      log(L_ERR "%s: Unexpected CoAP parser state in CLI endpoint", api->name);
      return false;

    case COAP_PS_ERROR:
      log(L_ERR "%s: CoAP parser error in CLI endpoint", api->name);
      return false;

    case COAP_PS_OPTION_PARTIAL:
    case COAP_PS_OPTION_COMPLETE:
      if (se->coap.parser.option_type & COAP_OPT_F_CRITICAL)
      {
	log(L_INFO "Unhandled option %u, fail", se->coap.parser.option_type);
	return yang_send_error_once(se, COAP_CERR_BAD_OPTION,
	    tmp_sprintf("Unhandled option %u", se->coap.parser.option_type));
      }
      return true;

    case COAP_PS_PAYLOAD_PARTIAL:
    case COAP_PS_PAYLOAD_COMPLETE:
      if (se->error_sent)
      {
	if (se->coap.parser.state == COAP_PS_PAYLOAD_COMPLETE)
	  se->endpoint = yang_default_endpoint;
	return true;
      }

      if (se->coap.parser.code != COAP_REQ_POST)
      {
	if (se->coap.parser.state == COAP_PS_PAYLOAD_COMPLETE)
	  se->endpoint = yang_default_endpoint;

	return yang_send_error_once(se, COAP_CERR_METHOD_NOT_ALLOWED,
	    "The CLI endpoint allows only POST/RPC calls");
      }

      bool done = yang_model_cli_cbor_c(se);
      if (se->coap.parser.state == COAP_PS_PAYLOAD_COMPLETE)
	se->endpoint = yang_default_endpoint;

      return done;
  }

  bug("this shall not happen");
}

static const struct yang_url_node
yang_model_cli_wellknown_core = {
  .endpoint = yang_model_cli_endpoint_wellknown_core,
  .stem = "core",
  .children = {
    NULL
  },
},
yang_model_cli_c = {
  .endpoint = yang_model_cli_endpoint_c,
  .stem = "c",
  .children = {
    NULL
  },
},
yang_model_cli_wellknown = {
  .stem = ".well-known",
  .children = {
    &yang_model_cli_wellknown_core,
    NULL
  },
},
yang_model_cli_root = {
  NULL, NULL, {
    &yang_model_cli_c,
    &yang_model_cli_wellknown,
    NULL
  },
};

const struct yang_url_node * const yang_url_tree[YANG_MODEL__MAX] = {
  NULL, &yang_model_cli_root,
};

static TLIST_LIST(yang_api) global_api_list;
static pool *yang_pool;

bool
yang_socket_same(const struct yang_socket_params *a, const struct yang_socket_params *b)
{
  if (a->kind != b->kind)
    return false;

  if (a->port != b->port)
    return false;

  if (!ipa_equal(a->local_ip, b->local_ip))
    return false;

  return true;
}

static bool
yang_api_same(const struct yang_api_params *a, const struct yang_api_params *b)
{
  if (a->restricted != b->restricted)
    return false;

  return true;
}

static void
yang_session_rx_option(struct yang_session *se)
{
  if (se->coap.parser.option_type > COAP_OPT_URI_PATH)
  {
    /* This should have been already resolved by COAP_OPT_URI_PATH
     * and ending up here means wrong path */
    log(L_INFO "Error 4.04: Not Found");
    yang_send_error_once(se, COAP_CERR_NOT_FOUND, "Not Found");
    return;
  }

  switch (se->coap.parser.option_type) {
    case COAP_OPT_URI_HOST:
      log(L_INFO "URI Host (%u-%u/%u): %.*s",
	  se->coap.parser.option_chunk_offset,
	  se->coap.parser.option_chunk_offset + se->coap.parser.option_chunk_len,
	  se->coap.parser.option_len,
	  se->coap.parser.option_chunk_len, se->coap.parser.option_value);
      return;

    case COAP_OPT_URI_PORT:
      log(L_INFO "URI Port");
      return;

    case COAP_OPT_URI_PATH:
      log(L_INFO "URI Path (%u-%u/%u): %.*s",
	  se->coap.parser.option_chunk_offset,
	  se->coap.parser.option_chunk_offset + se->coap.parser.option_chunk_len,
	  se->coap.parser.option_len,
	  se->coap.parser.option_chunk_len, se->coap.parser.option_value);

      ASSERT_DIE(se->url_pos == se->coap.parser.option_chunk_offset);

      while (*se->url)
	if (!strncmp(&(*se->url)->stem[se->url_pos], se->coap.parser.option_value, se->coap.parser.option_chunk_len))
	{
	  if (se->coap.parser.option_chunk_offset + se->coap.parser.option_chunk_len == se->coap.parser.option_len)
	  {
	    se->endpoint = ((*se->url)->endpoint) ?: yang_default_endpoint;
	    se->url = (*se->url)->children;
	    return;
	  }
	  break;
	}
	else
	  se->url++;

      if (!*se->url)
      {
	log(L_INFO "Error 4.04: Not Found");
	yang_send_error_once(se, COAP_CERR_NOT_FOUND, "Not Found");
      }

      return;

    default:
      if (se->coap.parser.option_type & COAP_OPT_F_CRITICAL)
      {
	log(L_INFO "Unhandled option %u, fail", se->coap.parser.option_type);
	yang_send_error_once(se, COAP_CERR_BAD_OPTION,
	    tmp_sprintf("Unhandled option %u", se->coap.parser.option_type));
      }
      return;
  }
}

static bool
yang_default_endpoint(struct yang_session *se)
{
  enum coap_parse_state state = se->coap.parser.state;
  struct yang_api *api = se->api;

  log(L_TRACE "state is %d", state);
  switch (state) {
    case COAP_PS_MORE:
      return false;

    case COAP_PS_ERROR:
      log(L_ERR "%s: CoAP error, closing", api->name);
      se->sock->rx_hook = NULL;
      return false;

    case COAP_PS_HEADER:
      /* Reset all required data structures so that we can process the options */
      se->error_sent = false;
      se->url = &yang_url_tree[api->params.model]->children[0];
      se->url_pos = 0;

      cbor_parser_reset(se->cbor);
      se->sid_stack[0] = 0;
      se->sid_pos = 0;
      se->sid_state = YANG_PS_VALUE;

      return true;

    case COAP_PS_OPTION_PARTIAL:
    case COAP_PS_OPTION_COMPLETE:
      yang_session_rx_option(se);
      return true;

    case COAP_PS_PAYLOAD_PARTIAL:
    case COAP_PS_PAYLOAD_COMPLETE:
      /* If found, the endpoint function should not be this one */
      log(L_INFO "Error 4.04: Not Found");
      return yang_send_error_once(se, COAP_CERR_NOT_FOUND, "Not Found");

    default:
      log(L_INFO "Dummy: Status %u", state);
      return false;
  }
}

static int
yang_session_rx(sock *sk, uint size)
{
  struct yang_session *se = sk->data;
  struct yang_api *api = se->api;

  log(L_TRACE "%s: RX data", api->name);

  /* Check the received data in */
  coap_tcp_rx(&se->coap, sk->rbuf, size);

  while (true)
  {
    /* Aggresively send data if possible */
    coap_tx_flush(&se->coap, sk);

    /* Next parser step */
    if (!coap_tcp_parse(&se->coap))
      return 1;

    /* It may be CoAP internal */
    if (coap_process(&se->coap))
      continue;

    /* Or the current endpoint will take care */
    if (se->endpoint(se))
      continue;

    /* Send remaining data if possible */
    coap_tx_flush(&se->coap, sk);
    return 1;
  }
}

static void
yang_session_tx(sock *sk)
{
  struct yang_session *se = sk->data;

  coap_tx_written(&se->coap, sk);
  coap_tx_flush(&se->coap, sk);
}

static void
yang_session_err(sock *sk, int err)
{
  struct yang_session *se = sk->data;
  struct yang_api *api = se->api;

  if (err)
    log(L_INFO "%s: Connection lost (%M)", api->name, err);
  else
    log(L_INFO "%s: Connection closed", api->name);

  sk_close(sk);
  cbor_parser_free(se->cbor);
  mb_free(se);
}

static int
yang_socket_accept(sock *sk, uint size UNUSED)
{
  struct yang_socket *s = sk->data;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  struct yang_session *se = mb_allocz(api->pool, sizeof *se);
  se->api = api;
  se->sock = sk;
  se->socket = s;
  se->endpoint = yang_default_endpoint;

  coap_session_init(&se->coap);
  se->cbor = cbor_parser_new(api->pool, 16);

  sk->rx_hook = yang_session_rx;
  sk->tx_hook = yang_session_tx;
  sk->err_hook = yang_session_err;
  sk->data = se;

  return 0;
}

static void
yang_listen_error(sock *sk, int err)
{
  struct yang_socket *s = sk->data;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  if (err == ECONNABORTED)
    log(L_WARN "%s: Incoming connection aborted", api->name);
  else
    log(L_ERR "%s: Error on listening socket: %M", err);
}

static void
yang_socket_olocked(void *_s)
{
  struct yang_socket *s = _s;
  SKIP_BACK_DECLARE(struct yang_api, api, listen, yang_socket_enlisted(s));

  ASSERT_DIE(!s->sock);
  s->sock = sock_new(api->pool);

  switch (s->params.kind)
  {
    case YANG_SOCKET_COAP_TCP:
      s->sock->pool = api->pool;
      s->sock->type = SK_TCP_PASSIVE;
      break;

    default:
      bug("Not implemented yet");
  }

  s->sock->saddr = s->params.local_ip;
  s->sock->sport = s->params.port;

  s->sock->rbsize = 16384;
  s->sock->tbsize = 16384;

  s->sock->rx_hook = yang_socket_accept;
  s->sock->err_hook = yang_listen_error;

  s->sock->data = s;

  if (sk_open(s->sock, &main_birdloop) < 0)
  {
    sk_log_error(s->sock, api->name);
    log(L_ERR "%s: Cannot open YANG listening socket", api->name);
    sk_close(s->sock);
    s->sock = NULL;
  }
}

static void
yang_socket_new(struct yang_api *api, struct yang_socket_config *sc)
{
  struct yang_socket *s = mb_allocz(api->pool, sizeof *s);

  s->config = sc;
  sc->socket = s;
  yang_socket_add_tail(&api->listen, s);

  s->params = sc->params;

  s->olock = olock_new(api->pool);
  s->olock->addr = sc->params.local_ip;
  s->olock->port = sc->params.port;
  s->olock->event.hook = yang_socket_olocked;
  s->olock->event.data = s;
  s->olock->target = &global_event_list;
  
  switch (sc->params.kind)
  {
    case YANG_SOCKET_COAP_TCP:
      s->olock->type = OBJLOCK_TCP;
      break;

    case YANG_SOCKET_COAP_UDP:
      s->olock->type = OBJLOCK_UDP;
      break;

    default:
      bug("Strange API endpoint kind: %d", sc->params.kind);
  }

  olock_acquire(s->olock);
}

static void
yang_socket_delete(struct yang_socket *s)
{
  struct yang_api *api = SKIP_BACK(struct yang_api, listen, yang_socket_enlisted(s));

  if (s->config)
    s->config->socket = NULL;

  if (s->sock)
    rfree(s->sock);

  if (s->olock)
    rfree(s->olock);

  yang_socket_rem_node(&api->listen, s);

#if 0
      switch (api->params.kind)
      {
	case YANG_SOCKET_COAP_TCP:
	  yang_socket_coap_tcp_delete(api);
	  break;

	case YANG_SOCKET_COAP_UDP:
	  yang_socket_coap_udp_delete(api);
	  break;

	default:
	  bug("Strange API endpoint kind: %d", api->params.kind);
      }
#endif
}

static void
yang_api_new(struct yang_api_config *ac)
{
  pool *p = rp_newf(yang_pool, yang_pool->domain, "YANG API %s", ac->name);
  struct yang_api *api = mb_allocz(p, sizeof *api);

  api->name = ac->name;
  api->pool = p;
  api->config = ac;
  api->params = ac->params;
  ac->api = api;

  yang_api_add_tail(&global_api_list, api);

  WALK_TLIST(yang_socket_config, sc, &ac->listen)
    yang_socket_new(api, sc);
}

static void
yang_api_delete(struct yang_api *api)
{
  WALK_TLIST_DELSAFE(yang_socket, s, &api->listen)
    yang_socket_delete(s);

  ASSERT_DIE(EMPTY_TLIST(yang_socket, &api->listen));

  api->config->api = NULL;
  yang_api_rem_node(&global_api_list, api);

  rp_free(api->pool);
}

static void
yang_api_reconfigure(struct yang_api *api)
{
  /* Match sockets to new config */
  WALK_TLIST(yang_socket_config, sc, &api->config->listen)
  {
    /* Looking for the same socket */
    WALK_TLIST(yang_socket, s, &api->listen)
      if (yang_socket_same(&s->params, &sc->params))
	/* Found same */
      {
	ASSERT_DIE(yang_socket_config_enlisted(s->config) != &api->config->listen);
	/* Drop the old config pointer */
	s->config->socket = NULL;

	/* Set the new pointers */
	s->config = sc;
	sc->socket = s;

	break;
      }

    /* Not found */
    if (!sc->socket)
      yang_socket_new(api, sc);
  }

  /* Delete sockets not defined in new config */
  WALK_TLIST_DELSAFE(yang_socket, s, &api->listen)
    if (yang_socket_config_enlisted(s->config) != &api->config->listen)
      yang_socket_delete(s);

}

void
yang_commit(struct config *new, struct config *old)
{
  /* Match running APIs to new config */
  WALK_TLIST(yang_api_config, ac, &new->yang)
  {

    /* Is there an API with the same name?
     * Note: We expect the users to not have lots of API endpoints configured,
     * and therefore this is ok being O(N^2). */
    WALK_TLIST(yang_api, api, &global_api_list)
      if (!strcmp(api->name, ac->name))
      {
	ASSERT_DIE(api->config->global == old);
	ASSERT_DIE(api->config->api == api);

	if (yang_api_same(&api->params, &ac->params))
	  /* Found same, keep */
	{
	  /* Drop the old config pointer */
	  api->config->api = NULL;

	  /* Set the new pointers */
	  api->config = ac;
	  ac->api = api;

	  /* The name is shared with the symbol */
	  api->name = ac->name;

	  /* Reconfigure sockets */
	  yang_api_reconfigure(api);
	}

	/* Otherwise, we just pretend nothing was found */
	break;
      }

    /* Found same, done */
    if (ac->api)
      continue;

    /* Make new API endpoint */
    yang_api_new(ac);
  }

  /* Find unmatched endpoints and delete them */
  WALK_TLIST_DELSAFE(yang_api, api, &global_api_list)
    if (api->config->global != new)
    {
      api->config->api = NULL;
      yang_api_delete(api);
    }

  /* Consistency check of the old config */
  WALK_TLIST(yang_api_config, ac, &new->yang)
    ASSERT_DIE(ac->api);
}

/**
 * yang_init - initialize needed YANG data structures on startup
 */
void
yang_init(void)
{
  yang_pool = rp_new(&root_pool, root_pool.domain, "YANG API toplevel");
}
