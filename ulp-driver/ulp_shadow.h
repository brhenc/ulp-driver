#ifndef _ULP_SHADOW_H
#define _ULP_SHADOW_H

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>

/**
 * ULP Shadow Variables Library
 * Allows livepatches to dynamically attach new metadata, fields, and state
 * to existing heap allocations/structures without altering structure sizes or memory layouts.
 */

#define ULP_SHADOW_BUCKETS 1024

struct ulp_shadow_node {
    const void *obj;
    uint64_t id;
    size_t size;
    void *data;
    struct ulp_shadow_node *next;
};

static struct {
    struct ulp_shadow_node *buckets[ULP_SHADOW_BUCKETS];
    pthread_mutex_t lock;
} g_ulp_shadow_table = { .lock = PTHREAD_MUTEX_INITIALIZER };

static inline uint32_t ulp_shadow_hash(const void *obj, uint64_t id)
{
    uint64_t h = (uint64_t)obj ^ (id * 0x9e3779b97f4a7c15ULL);
    return (uint32_t)((h ^ (h >> 32)) % ULP_SHADOW_BUCKETS);
}

static inline void *ulp_shadow_alloc(const void *obj, uint64_t id, size_t size, const void *init_data)
{
    if (!obj || size == 0) return NULL;

    uint32_t idx = ulp_shadow_hash(obj, id);
    struct ulp_shadow_node *node = (struct ulp_shadow_node *)malloc(sizeof(struct ulp_shadow_node));
    if (!node) return NULL;

    node->obj = obj;
    node->id = id;
    node->size = size;
    node->data = malloc(size);
    if (!node->data) {
        free(node);
        return NULL;
    }

    if (init_data) {
        memcpy(node->data, init_data, size);
    } else {
        memset(node->data, 0, size);
    }

    pthread_mutex_lock(&g_ulp_shadow_table.lock);
    node->next = g_ulp_shadow_table.buckets[idx];
    g_ulp_shadow_table.buckets[idx] = node;
    pthread_mutex_unlock(&g_ulp_shadow_table.lock);

    return node->data;
}

static inline void *ulp_shadow_get(const void *obj, uint64_t id)
{
    if (!obj) return NULL;

    uint32_t idx = ulp_shadow_hash(obj, id);
    void *res = NULL;

    pthread_mutex_lock(&g_ulp_shadow_table.lock);
    struct ulp_shadow_node *cur = g_ulp_shadow_table.buckets[idx];
    while (cur) {
        if (cur->obj == obj && cur->id == id) {
            res = cur->data;
            break;
        }
        cur = cur->next;
    }
    pthread_mutex_unlock(&g_ulp_shadow_table.lock);

    return res;
}

static inline void ulp_shadow_free(const void *obj, uint64_t id)
{
    if (!obj) return;

    uint32_t idx = ulp_shadow_hash(obj, id);

    pthread_mutex_lock(&g_ulp_shadow_table.lock);
    struct ulp_shadow_node **curr = &g_ulp_shadow_table.buckets[idx];
    while (*curr) {
        struct ulp_shadow_node *entry = *curr;
        if (entry->obj == obj && entry->id == id) {
            *curr = entry->next;
            free(entry->data);
            free(entry);
            break;
        }
        curr = &entry->next;
    }
    pthread_mutex_unlock(&g_ulp_shadow_table.lock);
}

#endif /* _ULP_SHADOW_H */
