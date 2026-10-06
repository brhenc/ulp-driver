#ifndef FRR_SHADOW_H
#define FRR_SHADOW_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Userspace Shadow Variable (USV) API for Livepatching
 * Modeled after the Linux kernel klp_shadow subsystem.
 *
 * Allows livepatches to attach arbitrary new fields/data to existing
 * heap-allocated structs (e.g. struct bgp_dest, struct peer) without
 * altering the struct size, memory layout, or breaking ABI.
 */

/* Allocate and attach shadow data of specified size to parent object pointer */
void *frr_shadow_alloc(const void *parent, uint32_t id, size_t size);

/* Get existing shadow data associated with parent object pointer, or NULL */
void *frr_shadow_get(const void *parent, uint32_t id);

/* Get existing shadow data, or allocate it if it does not exist yet */
void *frr_shadow_get_or_alloc(const void *parent, uint32_t id, size_t size);

/* Free shadow data associated with parent object pointer and id */
void frr_shadow_free(const void *parent, uint32_t id);

/* Free all shadow variables associated with parent (e.g. on parent destruction) */
void frr_shadow_free_all(const void *parent);

#ifdef __cplusplus
}
#endif

#endif /* FRR_SHADOW_H */
