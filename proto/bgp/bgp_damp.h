/*
 *	BIRD -- BGP Route Flap Dampening
 *
 *	This follows the FRR bgpd/bgp_damp.{c,h} algorithm, adapted to BIRD
 *	channel/rte storage.
 */

#ifndef _BIRD_BGP_DAMP_H_
#define _BIRD_BGP_DAMP_H_

#include "nest/bird.h"
#include "nest/route.h"
#include "lib/hash.h"
#include "lib/lists.h"
#include "lib/timer.h"

struct bgp_channel;
struct bgp_damp_info;

struct bgp_damp_config {
  uint enabled;

  uint suppress_value;
  uint reuse_limit;
  uint max_suppress_time;
  uint half_life;
};

struct bgp_damp_state {
  struct bgp_damp_config cfg;

  uint active;

  uint reuse_list_size;
  uint reuse_index_size;
  uint decay_array_size;
  uint reuse_offset;

  uint ceiling;
  double scale_factor;

  double *decay_array;
  int *reuse_index;
  list *reuse_list;
  list no_reuse_list;

  HASH(struct bgp_damp_info) info_hash;

  timer *reuse_timer;
};

#define BGP_DAMP_NONE		0
#define BGP_DAMP_USED		1
#define BGP_DAMP_SUPPRESSED	2

#define BGP_DAMP_DELTA_REUSE	10
#define BGP_DAMP_DELTA_T	5

#define BGP_DAMP_DEFAULT_PENALTY	1000
#define BGP_DAMP_DEFAULT_HALF_LIFE	15
#define BGP_DAMP_DEFAULT_REUSE		750
#define BGP_DAMP_DEFAULT_SUPPRESS	2000

#define BGP_DAMP_REUSE_LIST_SIZE	256
#define BGP_DAMP_REUSE_ARRAY_SIZE	1024

void bgp_damp_config_set(struct bgp_damp_config *cf, uint half, uint reuse,
			 uint suppress, uint max);
void bgp_damp_start(struct bgp_channel *c);
void bgp_damp_shutdown(struct bgp_channel *c);
void bgp_damp_refresh_begin(struct bgp_channel *c);
void bgp_damp_refresh_end(struct bgp_channel *c);

int bgp_damp_withdraw(struct bgp_channel *c, const net_addr *n,
		      struct rte_src *src, int attr_change);
int bgp_damp_update(struct bgp_channel *c, const net_addr *n,
		    struct rte_src *src, ea_list *attrs);
int bgp_damp_has_visible_route(struct bgp_channel *c, const net_addr *n,
			       struct rte_src *src);

#endif
