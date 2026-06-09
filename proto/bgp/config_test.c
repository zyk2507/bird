/*
 *	BGP: Configuration Tests
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "conf/conf.h"
#include "nest/protocol.h"
#include "proto/bgp/bgp.h"

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
parse_config(const char *text)
{
  struct config *cfg = config_alloc("bgp-config-test");

  test_config_pos = (const byte *) text;
  test_config_len = strlen(text);
  cf_read_hook = test_config_read;

  if (!config_parse(cfg) || cfg->err_msg)
  {
    bt_abort_msg("Parse failed at line %d: %s",
		 cfg->err_lino, cfg->err_msg ?: "unknown error");
  }

  return cfg;
}

static struct bgp_config *
find_bgp_config(struct config *cfg, const char *name)
{
  struct proto_config *pc;

  WALK_LIST(pc, cfg->protos)
    if ((pc->protocol == &proto_bgp) && !strcmp(pc->name, name))
      return (struct bgp_config *) pc;

  bt_abort_msg("BGP protocol %s not found", name);
  return NULL;
}

static struct bgp_channel_config *
find_bgp_channel_config(struct bgp_config *cf, u32 afi)
{
  struct bgp_channel_config *cc;

  BGP_CF_WALK_CHANNELS(cf, cc)
    if (cc->afi == afi)
      return cc;

  bt_abort_msg("BGP channel 0x%x not found", afi);
  return NULL;
}

static void
check_damp(const struct bgp_damp_config *damp, uint enabled, uint half,
	   uint reuse, uint suppress, uint max)
{
  bt_assert(damp->enabled == enabled);

  if (!enabled)
    return;

  bt_assert(damp->half_life == half * 60);
  bt_assert(damp->reuse_limit == reuse);
  bt_assert(damp->suppress_value == suppress);
  bt_assert(damp->max_suppress_time == max * 60);
}

static int
t_bgp_damp_proto_default(void)
{
  static const char cfg_text[] =
    "router id 192.0.2.254;\n"
    "\n"
    "protocol bgp p_default {\n"
    "  local as 65000;\n"
    "  neighbor 192.0.2.1 as 65001;\n"
    "  dampening 10 600 1800 40;\n"
    "\n"
    "  ipv4 {\n"
    "    import none;\n"
    "    export none;\n"
    "  };\n"
    "\n"
    "  ipv6 {\n"
    "    import none;\n"
    "    export none;\n"
    "    dampening off;\n"
    "  };\n"
    "}\n";

  struct config *cfg = parse_config(cfg_text);
  struct bgp_config *p = find_bgp_config(cfg, "p_default");
  struct bgp_channel_config *ipv4 = find_bgp_channel_config(p, BGP_AF_IPV4);
  struct bgp_channel_config *ipv6 = find_bgp_channel_config(p, BGP_AF_IPV6);

  bt_assert(p->damp_set);
  check_damp(&p->damp, 1, 10, 600, 1800, 40);

  bt_assert(!ipv4->damp_set);
  check_damp(&ipv4->damp, 1, 10, 600, 1800, 40);

  bt_assert(ipv6->damp_set);
  check_damp(&ipv6->damp, 0, 0, 0, 0, 0);

  config_free(cfg);
  return 1;
}

static int
t_bgp_damp_template_inheritance(void)
{
  static const char cfg_text[] =
    "router id 192.0.2.254;\n"
    "\n"
    "template bgp damp_tpl {\n"
    "  local as 65000;\n"
    "  dampening 20 800 2400 80;\n"
    "\n"
    "  ipv4 {\n"
    "    import none;\n"
    "    export none;\n"
    "  };\n"
    "\n"
    "  ipv6 {\n"
    "    import none;\n"
    "    export none;\n"
    "    dampening 5 500 1500 20;\n"
    "  };\n"
    "}\n"
    "\n"
    "protocol bgp p_inherit from damp_tpl {\n"
    "  neighbor 192.0.2.2 as 65002;\n"
    "}\n"
    "\n"
    "protocol bgp p_override from damp_tpl {\n"
    "  neighbor 192.0.2.3 as 65003;\n"
    "\n"
    "  ipv4 {\n"
    "    dampening off;\n"
    "  };\n"
    "}\n";

  struct config *cfg = parse_config(cfg_text);
  struct bgp_config *inherit = find_bgp_config(cfg, "p_inherit");
  struct bgp_config *override = find_bgp_config(cfg, "p_override");
  struct bgp_channel_config *inherit_ipv4 = find_bgp_channel_config(inherit, BGP_AF_IPV4);
  struct bgp_channel_config *inherit_ipv6 = find_bgp_channel_config(inherit, BGP_AF_IPV6);
  struct bgp_channel_config *override_ipv4 = find_bgp_channel_config(override, BGP_AF_IPV4);
  struct bgp_channel_config *override_ipv6 = find_bgp_channel_config(override, BGP_AF_IPV6);

  bt_assert(inherit->damp_set);
  check_damp(&inherit->damp, 1, 20, 800, 2400, 80);

  bt_assert(!inherit_ipv4->damp_set);
  check_damp(&inherit_ipv4->damp, 1, 20, 800, 2400, 80);

  bt_assert(inherit_ipv6->damp_set);
  check_damp(&inherit_ipv6->damp, 1, 5, 500, 1500, 20);

  bt_assert(override_ipv4->damp_set);
  check_damp(&override_ipv4->damp, 0, 0, 0, 0, 0);

  bt_assert(override_ipv6->damp_set);
  check_damp(&override_ipv6->damp, 1, 5, 500, 1500, 20);

  config_free(cfg);
  return 1;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);
  bt_bird_init();

  bt_test_suite(t_bgp_damp_proto_default,
		"BGP dampening protocol defaults");
  bt_test_suite(t_bgp_damp_template_inheritance,
		"BGP dampening template inheritance and channel override");

  return bt_exit_value();
}
