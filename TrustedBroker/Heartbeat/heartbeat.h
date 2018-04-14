#ifndef HEARTBEAT
#define HEARTBEAT

#include "hb_delivery.h"

typedef struct _sp_samp_heartbeat_data_t{
  uint8_t counter;
  uint8_t is_revoked; //0 is not revoked; 1 is revoked
}sp_samp_heartbeat_data_t;

int sp_heart_beat_loop(hb_samp_package_header_t **response);

#endif
