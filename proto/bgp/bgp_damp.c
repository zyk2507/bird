/*
 *	BIRD -- BGP Route Flap Dampening
 *
 *	Based on the route flap dampening implementation in FRR bgpd/bgp_damp.c.
 */

#include <limits.h>
#include <math.h>

#include "nest/bird.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "lib/hash.h"
#include "lib/resource.h"

#include "proto/bgp/bgp.h"
#include "proto/bgp/bgp_damp.h"

#define BGP_DAMP_NO_REUSE_LIST_INDEX	(-1)
#define BGP_DAMP_NO_LIST_INDEX		(-2)

#define BGP_RECORD_UPDATE		1
#define BGP_RECORD_WITHDRAW		2

struct bgp_damp_info {
  struct bgp_damp_info *next;
  node reuse_node;

  u32 hash;
  u64 path_id;

  uint penalty;
  uint flap;

  btime start_time;
  btime t_updated;
  btime suppress_time;

  struct bgp_channel *channel;
  struct rte_src *src;
  rta *last_rta;
  rta *stored_rta;

  int index;
  u8 lastrecord;
  u8 suppressed;
  u8 stale;

  net_addr net[0];
};


#define BDH_KEY(bdi)		bdi->net, bdi->path_id, bdi->hash
#define BDH_NEXT(bdi)		bdi->next
#define BDH_EQ(n1,p1,h1,n2,p2,h2) h1 == h2 && p1 == p2 && net_equal(n1, n2)
#define BDH_FN(n,p,h)		h

#define BDH_REHASH		bgp_damp_bdh_rehash
#define BDH_PARAMS		/8, *2, 2, 2, 8, 24

HASH_DEFINE_REHASH_FN(BDH, struct bgp_damp_info)

static void bgp_damp_reuse_timer(timer *t);


void
bgp_damp_config_set(struct bgp_damp_config *cf, uint half, uint reuse,
		    uint suppress, uint max)
{
  cf->enabled = 1;
  cf->half_life = half * 60;
  cf->reuse_limit = reuse;
  cf->suppress_value = suppress;
  cf->max_suppress_time = max * 60;
}

static inline int
bgp_damp_applicable(struct bgp_channel *c)
{
  struct bgp_proto *p = (void *) c->c.proto;

  return c->cf->damp.enabled && !p->is_interior;
}

static inline u32
bgp_damp_hash(const net_addr *n, u64 path_id)
{
  return u32_hash(net_hash(n) ^ u64_hash(path_id));
}

static struct bgp_damp_info *
bgp_damp_find(struct bgp_channel *c, const net_addr *n, struct rte_src *src)
{
  struct bgp_damp_state *st = &c->damp;

  if (!st->active)
    return NULL;

  u64 path_id = src->private_id;
  u32 hash = bgp_damp_hash(n, path_id);

  return HASH_FIND(st->info_hash, BDH, n, path_id, hash);
}

static void
bgp_damp_reuselist_add(struct bgp_damp_state *st, struct bgp_damp_info *bdi,
		       int index)
{
  bdi->index = index;

  if (index == BGP_DAMP_NO_REUSE_LIST_INDEX)
    add_head(&st->no_reuse_list, &bdi->reuse_node);
  else
    add_head(&st->reuse_list[index], &bdi->reuse_node);
}

static void
bgp_damp_reuselist_delete(struct bgp_damp_info *bdi)
{
  if (NODE_VALID(&bdi->reuse_node))
    rem_node(&bdi->reuse_node);

  bdi->index = BGP_DAMP_NO_LIST_INDEX;
}

static void
bgp_damp_reuselist_move(struct bgp_damp_state *st, struct bgp_damp_info *bdi,
			int index)
{
  bgp_damp_reuselist_delete(bdi);
  bgp_damp_reuselist_add(st, bdi, index);
}

static void
bgp_damp_clear_rta(rta **slot)
{
  if (!*slot)
    return;

  rta_free(*slot);
  *slot = NULL;
}

static void
bgp_damp_store_rta(rta **slot, rta *attrs)
{
  ASSERT(rta_is_cached(attrs));

  if (*slot == attrs)
    return;

  bgp_damp_clear_rta(slot);
  *slot = rta_clone(attrs);
}

static void
bgp_damp_clear_history(struct bgp_damp_info *bdi)
{
  bgp_damp_reuselist_delete(bdi);
  bdi->penalty = 0;
  bdi->flap = 0;
  bdi->suppress_time = 0;
  bdi->suppressed = 0;
}

static void
bgp_damp_release_route(struct bgp_damp_info *bdi)
{
  struct bgp_channel *c = bdi->channel;

  if (!bdi->stored_rta || (c->c.channel_state != CS_UP))
    return;

  rte *e = rte_get_temp(rta_clone(bdi->stored_rta), bdi->src);
  rte_update2(&c->c, bdi->net, e, bdi->src);
}

static void
bgp_damp_info_free(struct bgp_damp_info *bdi, int release_route)
{
  struct bgp_channel *c = bdi->channel;
  struct bgp_damp_state *st = &c->damp;

  if (release_route && bdi->lastrecord == BGP_RECORD_UPDATE)
    bgp_damp_release_route(bdi);

  bgp_damp_reuselist_delete(bdi);
  HASH_REMOVE(st->info_hash, BDH, bdi);

  bgp_damp_clear_rta(&bdi->last_rta);
  bgp_damp_clear_rta(&bdi->stored_rta);
  rt_unlock_source(bdi->src);
  mb_free(bdi);
}

static struct bgp_damp_info *
bgp_damp_get(struct bgp_channel *c, const net_addr *n, struct rte_src *src)
{
  struct bgp_damp_state *st = &c->damp;
  struct bgp_damp_info *bdi = bgp_damp_find(c, n, src);

  if (bdi)
    return bdi;

  bdi = mb_allocz(c->pool, sizeof(struct bgp_damp_info) + n->length);
  bdi->hash = bgp_damp_hash(n, src->private_id);
  bdi->path_id = src->private_id;
  bdi->channel = c;
  bdi->src = src;
  bdi->index = BGP_DAMP_NO_LIST_INDEX;
  rt_lock_source(src);
  net_copy(bdi->net, n);

  HASH_INSERT2(st->info_hash, BDH, c->pool, bdi);

  return bdi;
}

static int
bgp_damp_decay(uint tdiff, int penalty, struct bgp_damp_state *st)
{
  uint i = tdiff / BGP_DAMP_DELTA_T;

  if (i == 0)
    return penalty;

  if (i >= st->decay_array_size)
    return 0;

  return (int) (penalty * st->decay_array[i]);
}

static int
bgp_damp_reuse_index(uint penalty, struct bgp_damp_state *st)
{
  uint i, index;

  ASSERT(st->cfg.reuse_limit);

  if (penalty <= st->cfg.reuse_limit)
    i = 0;
  else
    i = (uint) ((((double) penalty / st->cfg.reuse_limit) - 1.0) *
		st->scale_factor);

  if (i >= st->reuse_index_size)
    i = st->reuse_index_size - 1;

  index = st->reuse_index[i] - st->reuse_index[0];

  return (st->reuse_offset + index) % st->reuse_list_size;
}

static void
bgp_damp_parameter_set(struct bgp_channel *c, struct bgp_damp_state *st)
{
  double reuse_max_ratio;
  double ceiling;
  uint i;
  double j;

  st->reuse_index_size = BGP_DAMP_REUSE_ARRAY_SIZE;

  ceiling = st->cfg.reuse_limit *
    pow(2, (double) st->cfg.max_suppress_time / st->cfg.half_life);
  st->ceiling = (ceiling > UINT_MAX) ? UINT_MAX : (uint) ceiling;

  st->decay_array_size =
    ceil((double) st->cfg.max_suppress_time / BGP_DAMP_DELTA_T);
  st->decay_array = mb_alloc(c->pool, sizeof(double) * st->decay_array_size);
  st->decay_array[0] = 1.0;
  st->decay_array[1] =
    pow(0.5, (double) BGP_DAMP_DELTA_T / st->cfg.half_life);

  for (i = 2; i < st->decay_array_size; i++)
    st->decay_array[i] = st->decay_array[i - 1] * st->decay_array[1];

  i = ceil((double) st->cfg.max_suppress_time / BGP_DAMP_DELTA_REUSE) + 1;
  if (i > BGP_DAMP_REUSE_LIST_SIZE || i == 0)
    i = BGP_DAMP_REUSE_LIST_SIZE;

  st->reuse_list_size = i;
  st->reuse_list = mb_alloc(c->pool, st->reuse_list_size * sizeof(list));
  for (i = 0; i < st->reuse_list_size; i++)
    init_list(&st->reuse_list[i]);

  st->reuse_index = mb_allocz(c->pool, sizeof(int) * st->reuse_index_size);

  reuse_max_ratio = (double) st->ceiling / st->cfg.reuse_limit;
  j = exp((double) st->cfg.max_suppress_time / st->cfg.half_life) *
    log10(2.0);
  if (reuse_max_ratio > j && j != 0)
    reuse_max_ratio = j;

  st->scale_factor = (double) st->reuse_index_size / (reuse_max_ratio - 1);

  for (i = 0; i < st->reuse_index_size; i++)
    st->reuse_index[i] =
      (int) (((double) st->cfg.half_life / BGP_DAMP_DELTA_REUSE) *
	     log10(1.0 / (st->cfg.reuse_limit *
			  (1.0 + ((double) i / st->scale_factor)))) /
	     log10(0.5));
}

void
bgp_damp_start(struct bgp_channel *c)
{
  struct bgp_damp_state *st = &c->damp;

  if (!bgp_damp_applicable(c))
    return;

  if (st->active)
    bgp_damp_shutdown(c);

  memset(st, 0, sizeof(*st));
  st->cfg = c->cf->damp;
  st->active = 1;

  init_list(&st->no_reuse_list);
  HASH_INIT(st->info_hash, c->pool, 8);

  bgp_damp_parameter_set(c, st);

  st->reuse_timer = tm_new_init(c->pool, bgp_damp_reuse_timer, c,
				BGP_DAMP_DELTA_REUSE S, 0);
  tm_start(st->reuse_timer, BGP_DAMP_DELTA_REUSE S);
}

static void
bgp_damp_cleanup(struct bgp_channel *c, int release_routes)
{
  struct bgp_damp_state *st = &c->damp;

  if (!st->active)
    return;

  if (st->reuse_timer)
    tm_stop(st->reuse_timer);

  HASH_WALK_DELSAFE(st->info_hash, next, bdi)
    bgp_damp_info_free(bdi, release_routes);
  HASH_WALK_DELSAFE_END;

  HASH_FREE(st->info_hash);

  mb_free(st->decay_array);
  mb_free(st->reuse_index);
  mb_free(st->reuse_list);

  memset(st, 0, sizeof(*st));
}

void
bgp_damp_shutdown(struct bgp_channel *c)
{
  bgp_damp_cleanup(c, 0);
}

void
bgp_damp_refresh_begin(struct bgp_channel *c)
{
  struct bgp_damp_state *st = &c->damp;

  if (!st->active)
    return;

  HASH_WALK(st->info_hash, next, bdi)
    bdi->stale = 1;
  HASH_WALK_END;
}

void
bgp_damp_refresh_end(struct bgp_channel *c)
{
  struct bgp_damp_state *st = &c->damp;

  if (!st->active)
    return;

  HASH_WALK_DELSAFE(st->info_hash, next, bdi)
    if (bdi->stale)
      bgp_damp_info_free(bdi, 0);
  HASH_WALK_DELSAFE_END;
}

int
bgp_damp_has_visible_route(struct bgp_channel *c, const net_addr *n,
			   struct rte_src *src)
{
  net *nn = net_find(c->c.table, n);
  rte *old = nn ? rte_find(nn, src) : NULL;

  return old && rte_is_valid(old);
}

int
bgp_damp_withdraw(struct bgp_channel *c, const net_addr *n,
		  struct rte_src *src, int attr_change)
{
  struct bgp_damp_state *st = &c->damp;
  struct bgp_damp_info *bdi;
  btime now;
  uint last_penalty = 0;
  int old_reachable;

  if (!st->active)
    return BGP_DAMP_USED;

  bdi = bgp_damp_find(c, n, src);
  old_reachable = bgp_damp_has_visible_route(c, n, src) ||
    (bdi && (bdi->last_rta || bdi->stored_rta));

  if (!bdi && !old_reachable)
    return BGP_DAMP_USED;

  now = current_time();

  if (!bdi)
  {
    bdi = bgp_damp_get(c, n, src);
    bdi->penalty = attr_change ? BGP_DAMP_DEFAULT_PENALTY / 2 :
      BGP_DAMP_DEFAULT_PENALTY;
    bdi->flap = 1;
    bdi->start_time = now;
    bgp_damp_reuselist_add(st, bdi, BGP_DAMP_NO_REUSE_LIST_INDEX);
  }
  else
  {
    last_penalty = bdi->penalty;
    bdi->penalty =
      bgp_damp_decay((now - bdi->t_updated) TO_S, bdi->penalty, st) +
      (attr_change ? BGP_DAMP_DEFAULT_PENALTY / 2 : BGP_DAMP_DEFAULT_PENALTY);

    if (bdi->penalty > st->ceiling)
      bdi->penalty = st->ceiling;

    bdi->flap++;
  }

  bdi->lastrecord = BGP_RECORD_WITHDRAW;
  bdi->t_updated = now;
  bdi->stale = 0;
  bgp_damp_clear_rta(&bdi->stored_rta);
  if (!attr_change)
    bgp_damp_clear_rta(&bdi->last_rta);

  if (bdi->suppressed)
  {
    if (bdi->penalty != last_penalty)
      bgp_damp_reuselist_move(st, bdi, bgp_damp_reuse_index(bdi->penalty, st));

    return BGP_DAMP_SUPPRESSED;
  }

  if (bdi->index == BGP_DAMP_NO_LIST_INDEX)
    bgp_damp_reuselist_add(st, bdi, BGP_DAMP_NO_REUSE_LIST_INDEX);

  if (bdi->penalty >= st->cfg.suppress_value)
  {
    bdi->suppressed = 1;
    bdi->suppress_time = now;
    bgp_damp_reuselist_move(st, bdi, bgp_damp_reuse_index(bdi->penalty, st));
  }

  return BGP_DAMP_USED;
}

int
bgp_damp_update(struct bgp_channel *c, const net_addr *n,
		struct rte_src *src, rta *attrs)
{
  struct bgp_damp_state *st = &c->damp;
  struct bgp_damp_info *bdi;
  btime now;
  int status;

  if (!st->active)
    return BGP_DAMP_USED;

  ASSERT(rta_is_cached(attrs));

  bdi = bgp_damp_find(c, n, src);

  if (bdi && bdi->last_rta && (bdi->last_rta != attrs))
    bgp_damp_withdraw(c, n, src, 1);

  bdi = bgp_damp_find(c, n, src);

  if (!bdi)
  {
    bdi = bgp_damp_get(c, n, src);
    bdi->start_time = current_time();
  }

  now = current_time();
  bdi->lastrecord = BGP_RECORD_UPDATE;
  bdi->stale = 0;
  bdi->penalty = bgp_damp_decay((now - bdi->t_updated) TO_S, bdi->penalty, st);

  if (!bdi->suppressed && (bdi->penalty < st->cfg.suppress_value))
    status = BGP_DAMP_USED;
  else if (bdi->suppressed && (bdi->penalty < st->cfg.reuse_limit))
  {
    bdi->suppressed = 0;
    bdi->suppress_time = 0;
    bgp_damp_reuselist_move(st, bdi, BGP_DAMP_NO_REUSE_LIST_INDEX);
    status = BGP_DAMP_USED;
  }
  else
    status = BGP_DAMP_SUPPRESSED;

  if (status == BGP_DAMP_SUPPRESSED)
  {
    bgp_damp_store_rta(&bdi->last_rta, attrs);
    bgp_damp_store_rta(&bdi->stored_rta, attrs);
    if (bdi->penalty > st->cfg.reuse_limit / 2)
      bdi->t_updated = now;

    return status;
  }

  bgp_damp_store_rta(&bdi->last_rta, attrs);
  bgp_damp_clear_rta(&bdi->stored_rta);

  if (bdi->penalty > st->cfg.reuse_limit / 2)
  {
    if (bdi->index == BGP_DAMP_NO_LIST_INDEX)
      bgp_damp_reuselist_add(st, bdi, BGP_DAMP_NO_REUSE_LIST_INDEX);

    bdi->t_updated = now;
  }
  else
  {
    bgp_damp_clear_history(bdi);
    bdi->t_updated = now;
  }

  return status;
}

static void
bgp_damp_reuse_timer(timer *t)
{
  struct bgp_channel *c = t->data;
  struct bgp_damp_state *st = &c->damp;
  btime now = current_time();
  list work;
  uint offset;

  if (!st->active)
    return;

  ASSERT(st->reuse_offset < st->reuse_list_size);
  offset = st->reuse_offset;

  init_list(&work);
  while (!EMPTY_LIST(st->reuse_list[offset]))
  {
    node *n = HEAD(st->reuse_list[offset]);
    rem_node(n);
    add_tail(&work, n);
  }

  st->reuse_offset = (st->reuse_offset + 1) % st->reuse_list_size;

  while (!EMPTY_LIST(work))
  {
    node *n = HEAD(work);
    struct bgp_damp_info *bdi;

    rem_node(n);
    bdi = SKIP_BACK(struct bgp_damp_info, reuse_node, n);
    bdi->index = BGP_DAMP_NO_LIST_INDEX;

    bdi->penalty = bgp_damp_decay((now - bdi->t_updated) TO_S,
				  bdi->penalty, st);
    bdi->t_updated = now;

    if (bdi->penalty < st->cfg.reuse_limit)
    {
      bdi->suppressed = 0;
      bdi->suppress_time = 0;

      if (bdi->lastrecord == BGP_RECORD_UPDATE)
	bgp_damp_release_route(bdi);

      if (bdi->penalty <= st->cfg.reuse_limit / 2)
      {
	if (bdi->lastrecord == BGP_RECORD_UPDATE)
	{
	  bgp_damp_clear_rta(&bdi->stored_rta);
	  bgp_damp_clear_history(bdi);
	  bdi->t_updated = now;
	}
	else
	  bgp_damp_info_free(bdi, 0);
      }
      else
      {
	bgp_damp_clear_rta(&bdi->stored_rta);
	bgp_damp_reuselist_add(st, bdi, BGP_DAMP_NO_REUSE_LIST_INDEX);
      }
    }
    else
      bgp_damp_reuselist_add(st, bdi,
			     bgp_damp_reuse_index(bdi->penalty, st));
  }
}
