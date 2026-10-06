#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>

#include <haproxy/api.h>
#include <haproxy/proxy.h>
#include <haproxy/stick_table.h>
#include <haproxy/compression.h>
#include <haproxy/listener.h>
#include <haproxy/counters.h>
#include <haproxy/filters.h>
#include <haproxy/task.h>
#include <haproxy/pool.h>
#include <haproxy/guid.h>
#include <import/ebtree.h>
#include <import/eb32tree.h>
#include <import/ebmbtree.h>

#define ebmb_delete(node) eb_delete(&(node)->node)

/* Forward declaration / implementation of patched deinit_comp */
void livepatch_deinit_comp(struct comp *comp)
{
	struct comp_type *type, *next_type;
	struct comp_algo *algo, *next_algo;

	if (!comp)
		return;

	for (type = comp->types_req; type; type = next_type) {
		next_type = type->next;
		free(type->name);
		free(type);
	}
	for (type = comp->types_res; type; type = next_type) {
		next_type = type->next;
		free(type->name);
		free(type);
	}
	for (algo = comp->algos_res; algo; algo = next_algo) {
		next_algo = algo->next;
		free(algo);
	}
	for (algo = comp->algo_req; algo; algo = next_algo) {
		next_algo = algo->next;
		free(algo);
	}
	free(comp);
}

/* Patched stktable_deinit implementation */
void livepatch_stktable_deinit(struct stktable *t)
{
	struct ebmb_node *node;
	struct stksess *ts;
	int i;

	syslog(LOG_NOTICE, "[ULP-HAPROXY-LIVEPATCH] livepatch_stktable_deinit called for table %p\n", t);

	if (!t)
		return;

	for (i = 0; i < CONFIG_HAP_TBL_BUCKETS; i++) {
		while ((node = ebmb_first(&t->buckets[i].keys))) {
			ts = ebmb_entry(node, struct stksess, key);
			eb_delete(&ts->key.node);
			eb32_delete(&ts->exp);
			eb32_delete(&ts->upd);
			stksess_free(t, ts);
		}
	}
	for (i = 0; i < CONFIG_HAP_TBL_BUCKETS; i++) {
		HA_SPIN_LOCK(OTHER_LOCK, &per_bucket[i].lock);
		eb32_delete(&t->buckets[i].in_bucket);
		MT_LIST_DELETE(&t->buckets[i].in_bucket_toadd);
		HA_SPIN_UNLOCK(OTHER_LOCK, &per_bucket[i].lock);
	}
	tasklet_free(t->updt_task);
	ha_free(&t->pend_updts);
	pool_destroy(t->pool);
}

/* Patched deinit_proxy implementation */
void livepatch_deinit_proxy(struct proxy *p)
{
	struct listener *l, *l_next;
	struct bind_conf *bind_conf, *bind_back;
	struct proxy_deinit_fct *pxdf;

	syslog(LOG_NOTICE, "[ULP-HAPROXY-LIVEPATCH] livepatch_deinit_proxy called for proxy %s\n",
	       p ? p->id : "null");

	if (!p)
		return;

	if (p->lbprm.ops && p->lbprm.ops->proxy_deinit)
		p->lbprm.ops->proxy_deinit(p);

	list_for_each_entry_safe(l, l_next, &p->conf.listeners, by_fe) {
		guid_remove(&l->guid);
		LIST_DELETE(&l->by_fe);
		LIST_DELETE(&l->by_bind);
		shard_info_detach(&l->rx);
		free(l->name);
		free(l->label);
		free(l->per_thr);
		if (l->counters) {
			counters_fe_shared_drop(&l->counters->shared);
			free(l->counters);
		}
		task_destroy(l->rx.rhttp.task);

		EXTRA_COUNTERS_FREE(l->extra_counters);
		free(l);
	}

	/* Release unused SSL configs. */
	list_for_each_entry_safe(bind_conf, bind_back, &p->conf.bind, by_fe) {
		if (bind_conf->xprt->destroy_bind_conf)
			bind_conf->xprt->destroy_bind_conf(bind_conf);
		free(bind_conf->file);
		free(bind_conf->arg);
		free(bind_conf->settings.interface);
		LIST_DELETE(&bind_conf->by_fe);
		free(bind_conf->guid_prefix);
		free(bind_conf->rhttp_srvname);
		free(bind_conf->tcp_md5sig);
		free(bind_conf->cc_algo);
		free(bind_conf);
	}

	flt_deinit(p);

	list_for_each_entry(pxdf, &proxy_deinit_list, list)
		pxdf->fct(p);

	free(p->desc);

	task_destroy(p->task);

	pool_destroy(p->req_cap_pool);
	pool_destroy(p->rsp_cap_pool);

	livepatch_stktable_deinit(p->table);
	ha_free(&p->table);
	ha_free(&p->per_tgrp);

	HA_RWLOCK_DESTROY(&p->lbprm.lock);
	HA_RWLOCK_DESTROY(&p->lock);

	if (p->comp && (!p->defpx || p->comp != p->defpx->comp)) {
		livepatch_deinit_comp(p->comp);
		p->comp = NULL;
	}

	proxy_unref_defaults(p);
}
