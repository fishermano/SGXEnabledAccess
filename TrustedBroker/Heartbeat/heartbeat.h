#ifndef HEARTBEAT
#define HEARTBEAT

#include "network.h"

typedef struct _sp_samp_heartbeat_data_t{
  uint8_t counter;
  uint8_t is_revoked; //0 is not revoked; 1 is revoked
}sp_samp_heartbeat_data_t;

int sp_hb_generate(pkg_header_t **response);

#endif
