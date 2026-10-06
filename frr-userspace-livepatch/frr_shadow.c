#include "frr_shadow.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define SHADOW_BUCKETS 1024
#define SHADOW_MAX_CHAIN_LEN 4096

struct shadow_node {
    const void *parent;
    uint32_t id;
    size_t size;
    struct shadow_node *next;
    char data[] __attribute__((aligned(8)));
};

struct shadow_bucket {
    struct shadow_node *head;
    pthread_rwlock_t lock;
};

static struct shadow_bucket g_shadow_buckets[SHADOW_BUCKETS];
static pthread_once_t g_shadow_init_once = PTHREAD_ONCE_INIT;

static void shadow_table_init(void)
{
    for (size_t i = 0; i < SHADOW_BUCKETS; i++) {
        g_shadow_buckets[i].head = NULL;
        pthread_rwlock_init(&g_shadow_buckets[i].lock, NULL);
    }
}

static inline void ensure_initialized(void)
{
    pthread_once(&g_shadow_init_once, shadow_table_init);
}

static inline size_t shadow_hash(const void *parent, uint32_t id)
{
    uintptr_t p = (uintptr_t)parent;
    return ((p >> 4) ^ id ^ (p >> 12)) % SHADOW_BUCKETS;
}

void *frr_shadow_alloc(const void *parent, uint32_t id, size_t size)
{
    if (!parent || size == 0) return NULL;
    ensure_initialized();

    size_t bidx = shadow_hash(parent, id);
    struct shadow_bucket *bucket = &g_shadow_buckets[bidx];

    struct shadow_node *node = malloc(sizeof(struct shadow_node) + size);
    if (!node) return NULL;

    node->parent = parent;
    node->id = id;
    node->size = size;
    memset(node->data, 0, size);

    pthread_rwlock_wrlock(&bucket->lock);
    node->next = bucket->head;
    bucket->head = node;
    pthread_rwlock_unlock(&bucket->lock);

    return node->data;
}

void *frr_shadow_get(const void *parent, uint32_t id)
{
    if (!parent) return NULL;
    ensure_initialized();

    size_t bidx = shadow_hash(parent, id);
    struct shadow_bucket *bucket = &g_shadow_buckets[bidx];
    void *ret = NULL;
    size_t iters = 0;

    pthread_rwlock_rdlock(&bucket->lock);
    struct shadow_node *cur = bucket->head;
    while (cur && ++iters <= SHADOW_MAX_CHAIN_LEN) {
        if (cur->parent == parent && cur->id == id) {
            ret = cur->data;
            break;
        }
        cur = cur->next;
    }
    pthread_rwlock_unlock(&bucket->lock);

    return ret;
}

/* Double-checked lock allocation preventing duplicate shadow nodes with bounded loops */
void *frr_shadow_get_or_alloc(const void *parent, uint32_t id, size_t size)
{
    if (!parent || size == 0) return NULL;
    ensure_initialized();

    size_t bidx = shadow_hash(parent, id);
    struct shadow_bucket *bucket = &g_shadow_buckets[bidx];
    size_t iters = 0;

    /* 1. Fast path: Read lock check */
    pthread_rwlock_rdlock(&bucket->lock);
    struct shadow_node *cur = bucket->head;
    while (cur && ++iters <= SHADOW_MAX_CHAIN_LEN) {
        if (cur->parent == parent && cur->id == id) {
            void *data = cur->data;
            pthread_rwlock_unlock(&bucket->lock);
            return data;
        }
        cur = cur->next;
    }
    pthread_rwlock_unlock(&bucket->lock);

    /* 2. Allocate candidate node outside critical section */
    struct shadow_node *node = malloc(sizeof(struct shadow_node) + size);
    if (!node) return NULL;

    node->parent = parent;
    node->id = id;
    node->size = size;
    memset(node->data, 0, size);

    /* 3. Slow path: Acquire write lock and re-verify under lock */
    iters = 0;
    pthread_rwlock_wrlock(&bucket->lock);
    cur = bucket->head;
    while (cur && ++iters <= SHADOW_MAX_CHAIN_LEN) {
        if (cur->parent == parent && cur->id == id) {
            /* Another thread won the race while we were allocating */
            pthread_rwlock_unlock(&bucket->lock);
            free(node);
            return cur->data;
        }
        cur = cur->next;
    }

    node->next = bucket->head;
    bucket->head = node;
    pthread_rwlock_unlock(&bucket->lock);

    return node->data;
}

void frr_shadow_free(const void *parent, uint32_t id)
{
    if (!parent) return;
    ensure_initialized();

    size_t bidx = shadow_hash(parent, id);
    struct shadow_bucket *bucket = &g_shadow_buckets[bidx];
    size_t iters = 0;

    pthread_rwlock_wrlock(&bucket->lock);
    struct shadow_node **pprev = &bucket->head;
    while (*pprev && ++iters <= SHADOW_MAX_CHAIN_LEN) {
        struct shadow_node *cur = *pprev;
        if (cur->parent == parent && cur->id == id) {
            *pprev = cur->next;
            free(cur);
            break;
        }
        pprev = &cur->next;
    }
    pthread_rwlock_unlock(&bucket->lock);
}

void frr_shadow_free_all(const void *parent)
{
    if (!parent) return;
    ensure_initialized();

    for (size_t i = 0; i < SHADOW_BUCKETS; i++) {
        struct shadow_bucket *bucket = &g_shadow_buckets[i];
        size_t iters = 0;
        pthread_rwlock_wrlock(&bucket->lock);
        struct shadow_node **pprev = &bucket->head;
        while (*pprev && ++iters <= SHADOW_MAX_CHAIN_LEN) {
            struct shadow_node *cur = *pprev;
            if (cur->parent == parent) {
                *pprev = cur->next;
                free(cur);
            } else {
                pprev = &cur->next;
            }
        }
        pthread_rwlock_unlock(&bucket->lock);
    }
}
