#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "frr_shadow.h"

#define SHADOW_KEY_BGP_METRIC 0x42475031 // 'BGP1'

struct bgp_livepatch_metadata {
    uint64_t invocation_count;
    uint64_t custom_route_tag;
};

// The Livepatched Replacement Function with Shadow Variables
int livepatch_bgp_show_summary_vty(void *vty, const char *name, int afi, int safi, int is_json, int uj)
{
    // Retrieve or allocate dynamic shadow variable attached to this vty pointer
    struct bgp_livepatch_metadata *meta = frr_shadow_get_or_alloc(vty ? vty : (void*)0x1,
                                                                   SHADOW_KEY_BGP_METRIC,
                                                                   sizeof(*meta));
    if (meta) {
        meta->invocation_count++;
        meta->custom_route_tag = 0xDEB130000000ULL + meta->invocation_count;
    }

    syslog(LOG_ERR, "[ULP-DEBIAN-13-LIVEPATCH] PID: %d | Count: %lu | Tag: 0x%lx",
           getpid(),
           meta ? meta->invocation_count : 0,
           meta ? meta->custom_route_tag : 0);

    return 0; // CMD_SUCCESS
}
