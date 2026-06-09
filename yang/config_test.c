/*
 *	BIRD -- YANG API Configuration Tests
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "conf/conf.h"
#include "yang/yang.h"

static const byte *test_config_pos;
static uint test_config_len;

static int
test_config_read(byte *dest, uint max_len, int fd UNUSED)
{
  max_len = MIN(max_len, test_config_len);
  memcpy(dest, test_config_pos, max_len);
  test_config_pos += max_len;
  test_config_len -= max_len;
  return max_len;
}

static struct config *
parse_config_ok(const char *text)
{
  struct config *cfg = config_alloc("yang-config-test");

  test_config_pos = (const byte *) text;
  test_config_len = strlen(text);
  cf_read_hook = test_config_read;

  if (!config_parse(cfg) || cfg->err_msg)
    bt_abort_msg("Parse failed at line %d: %s",
		 cfg->err_lino, cfg->err_msg ?: "unknown error");

  return cfg;
}

static int
parse_config_fails(const char *text, const char *msg)
{
  struct config *cfg = config_alloc("yang-config-test-fail");

  test_config_pos = (const byte *) text;
  test_config_len = strlen(text);
  cf_read_hook = test_config_read;

  int ok = config_parse(cfg) && !cfg->err_msg;
  int matched = !ok && cfg->err_msg && strstr(cfg->err_msg, msg);
  bt_assert_msg(!ok, "Config must fail to parse");
  bt_assert_msg(matched, "Expected error containing '%s', got '%s'",
		msg, cfg->err_msg ?: "<none>");

  config_free(cfg);
  return !ok && matched;
}

static int
t_yang_explicit_tcp_coap(void)
{
  static const char cfg_text[] =
    "router id 192.0.2.1;\n"
    "protocol device {}\n"
    "yang mgmt {\n"
    "  model cli;\n"
    "  restricted yes;\n"
    "  listen tcp coap {\n"
    "    local 127.0.0.1;\n"
    "    port 15683;\n"
    "  };\n"
    "}\n";

  struct config *cfg = parse_config_ok(cfg_text);

  bt_assert(!EMPTY_TLIST(yang_api_config, &cfg->yang));

  struct yang_api_config *api = cfg->yang.first;
  bt_assert(!strcmp(api->name, "mgmt"));
  bt_assert(api->params.model == YANG_MODEL_CLI);
  bt_assert(api->params.restricted);

  bt_assert(!EMPTY_TLIST(yang_socket_config, &api->listen));
  struct yang_socket_config *sc = api->listen.first;
  bt_assert(sc->params.kind == YANG_SOCKET_COAP_TCP);
  bt_assert(sc->params.port == 15683);
  bt_assert(ipa_equal(sc->params.local_ip, ipa_build4(127, 0, 0, 1)));
  bt_assert(sc->socket == NULL);

  config_free(cfg);
  return 1;
}

static int
t_yang_default_name_and_socket(void)
{
  static const char cfg_text[] =
    "router id 192.0.2.1;\n"
    "protocol device {}\n"
    "yang {\n"
    "  model cli;\n"
    "  listen tcp coap {};\n"
    "}\n";

  struct config *cfg = parse_config_ok(cfg_text);
  struct yang_api_config *api = cfg->yang.first;
  struct yang_socket_config *sc = api->listen.first;

  bt_assert(!strcmp(api->name, "yang1"));
  bt_assert(api->params.model == YANG_MODEL_CLI);
  bt_assert(!api->params.restricted);
  bt_assert(sc->params.kind == YANG_SOCKET_COAP_TCP);
  bt_assert(sc->params.port == 5683);
  bt_assert(ipa_equal(sc->params.local_ip, ipa_build6(0, 0, 0, 1)));

  config_free(cfg);
  return 1;
}

static int
t_yang_duplicate_socket_rejected(void)
{
  static const char cfg_text[] =
    "router id 192.0.2.1;\n"
    "protocol device {}\n"
    "yang mgmt {\n"
    "  model cli;\n"
    "  listen tcp coap { local 127.0.0.1; port 15683; };\n"
    "  listen tcp coap { local 127.0.0.1; port 15683; };\n"
    "}\n";

  return parse_config_fails(cfg_text, "Duplicate socket configuration");
}

static int
t_yang_udp_socket_rejected(void)
{
  static const char cfg_text[] =
    "router id 192.0.2.1;\n"
    "protocol device {}\n"
    "yang mgmt {\n"
    "  model cli;\n"
    "  listen udp coap { local 127.0.0.1; port 15683; };\n"
    "}\n";

  return parse_config_fails(cfg_text, "YANG UDP CoAP sockets are not supported yet");
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);
  bt_bird_init();

  bt_test_suite(t_yang_explicit_tcp_coap,
		"YANG API explicit TCP CoAP parser configuration");
  bt_test_suite(t_yang_default_name_and_socket,
		"YANG API default name and TCP CoAP socket values");
  bt_test_suite(t_yang_duplicate_socket_rejected,
		"YANG API duplicate socket rejection");
  bt_test_suite(t_yang_udp_socket_rejected,
		"YANG API UDP CoAP socket rejection");

  return bt_exit_value();
}
