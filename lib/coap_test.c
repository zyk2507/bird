/*
 *	BIRD -- CoAP Library Tests
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "lib/coap.h"

static void
coap_test_init(struct coap_session *s)
{
  coap_session_init(s);

  while (!EMPTY_TLIST(coap_tx, &s->tx_queue))
  {
    struct coap_tx *tx = s->tx_queue.first;
    coap_tx_rem_node(&s->tx_queue, tx);
    free_page(tx);
  }
}

static int
t_coap_tcp_csm_processing(void)
{
  struct coap_session s;
  coap_test_init(&s);

  static const char frame[] = { 0x00, COAP_SCO_CSM };
  coap_tcp_rx(&s, frame, sizeof(frame));

  bt_assert(coap_tcp_parse(&s));
  bt_assert(s.parser.state == COAP_PS_HEADER);
  bt_assert(s.parser.code == COAP_SCO_CSM);
  bt_assert(coap_process(&s));
  bt_assert(s.blockwise_rx);

  bt_assert(coap_tcp_parse(&s));
  bt_assert(s.parser.state == COAP_PS_PAYLOAD_COMPLETE);
  bt_assert(coap_process(&s));
  bt_assert(s.parser.code == 0);

  return 1;
}

static int
t_coap_tcp_get_uri_path(void)
{
  struct coap_session s;
  coap_test_init(&s);

  static const char frame[] = {
    0xd0, 0x04, COAP_REQ_GET,
    0xbb, '.', 'w', 'e', 'l', 'l', '-', 'k', 'n', 'o', 'w', 'n',
    0x04, 'c', 'o', 'r', 'e',
  };

  coap_tcp_rx(&s, frame, sizeof(frame));

  bt_assert(coap_tcp_parse(&s));
  bt_assert(s.parser.state == COAP_PS_HEADER);
  bt_assert(s.parser.code == COAP_REQ_GET);

  bt_assert(coap_tcp_parse(&s));
  bt_assert(s.parser.state == COAP_PS_OPTION_COMPLETE);
  bt_assert(s.parser.option_type == COAP_OPT_URI_PATH);
  bt_assert(s.parser.option_len == 11);
  bt_assert(s.parser.option_chunk_len == 11);
  bt_assert(!memcmp(s.parser.option_value, ".well-known", 11));

  bt_assert(coap_tcp_parse(&s));
  bt_assert(s.parser.state == COAP_PS_OPTION_COMPLETE);
  bt_assert(s.parser.option_type == COAP_OPT_URI_PATH);
  bt_assert(s.parser.option_len == 4);
  bt_assert(s.parser.option_chunk_len == 4);
  bt_assert(!memcmp(s.parser.option_value, "core", 4));

  bt_assert(coap_tcp_parse(&s));
  bt_assert(s.parser.state == COAP_PS_PAYLOAD_COMPLETE);
  bt_assert(s.parser.payload_total_len == 0);

  return 1;
}

static int
t_coap_tcp_post_payload(void)
{
  struct coap_session s;
  coap_test_init(&s);

  static const char frame[] = {
    0x60, COAP_REQ_POST,
    0xb1, 'c',
    0xff, 0xa1, 0x01, 0xf6,
  };

  coap_tcp_rx(&s, frame, sizeof(frame));

  bt_assert(coap_tcp_parse(&s));
  bt_assert(s.parser.state == COAP_PS_HEADER);
  bt_assert(s.parser.code == COAP_REQ_POST);

  bt_assert(coap_tcp_parse(&s));
  bt_assert(s.parser.state == COAP_PS_OPTION_COMPLETE);
  bt_assert(s.parser.option_type == COAP_OPT_URI_PATH);
  bt_assert(s.parser.option_len == 1);
  bt_assert(!memcmp(s.parser.option_value, "c", 1));

  bt_assert(coap_tcp_parse(&s));
  bt_assert(s.parser.state == COAP_PS_PAYLOAD_COMPLETE);
  bt_assert(s.parser.payload_total_len == 3);
  bt_assert(s.parser.payload_chunk_len == 3);
  bt_assert(!memcmp(s.parser.payload, "\xa1\x01\xf6", 3));

  return 1;
}

static int
t_coap_tcp_tx_response(void)
{
  struct coap_session s;
  coap_test_init(&s);

  s.parser.token_len = 2;
  s.parser.token[0] = 'x';
  s.parser.token[1] = 'y';

  struct coap_tx_option
    *content_format = COAP_TX_OPTION_INT(COAP_OPT_CONTENT_FORMAT, (u8) 140),
    *payload = COAP_TX_OPTION_PRINTF(0, "ok");

  coap_tx_send(&s, COAP_TX_RESPONSE(&s, COAP_RESP_CONTENT, content_format, payload));

  struct coap_tx *tx = s.tx_queue.first;
  bt_assert(tx);

  static const byte expected[] = {
    0x52, COAP_RESP_CONTENT, 'x', 'y',
    0xc1, 0x8c,
    0xff, 'o', 'k',
  };

  uint len = tx->buf.pos - tx->buf.start;
  bt_assert_msg(len == sizeof(expected), "TX length %u expected %u", len, (uint) sizeof(expected));
  bt_assert(!memcmp(tx->buf.start, expected, sizeof(expected)));

  coap_tx_rem_node(&s.tx_queue, tx);
  free_page(tx);
  return 1;
}

static int
t_coap_tcp_rejects_invalid_token_length(void)
{
  struct coap_session s;
  coap_test_init(&s);

  static const char frame[] = { 0x09 };
  coap_tcp_rx(&s, frame, sizeof(frame));

  bt_assert(!coap_tcp_parse(&s));
  bt_assert(s.parser.state == COAP_PSE_INVALID_TOKLEN);

  return 1;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_coap_tcp_csm_processing, "CoAP TCP CSM processing");
  bt_test_suite(t_coap_tcp_get_uri_path, "CoAP TCP GET URI path parsing");
  bt_test_suite(t_coap_tcp_post_payload, "CoAP TCP POST payload parsing");
  bt_test_suite(t_coap_tcp_tx_response, "CoAP TCP response frame encoding");
  bt_test_suite(t_coap_tcp_rejects_invalid_token_length, "CoAP TCP invalid token length handling");

  return bt_exit_value();
}
