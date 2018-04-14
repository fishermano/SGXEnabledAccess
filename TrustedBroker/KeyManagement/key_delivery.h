#ifndef _KEY_DELIVERY_H
#define _KEY_DELIVERY_H

#include <stdint.h>

typedef enum _kd_msg_type_t{
  TYPE_KEY_REQUEST,
  TYPE_KEY_RESPONSE,
}kd_msg_type_t;

#pragma pack(1)
typedef struct _kd_samp_package_header_t{
  uint8_t type;
  uint32_t size;
  uint8_t align[3];
  uint8_t body[];
}kd_samp_package_header_t;
#pragma pack()

#endif
