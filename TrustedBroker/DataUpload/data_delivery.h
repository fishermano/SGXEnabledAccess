#ifndef _DATA_DELIVERY_H
#define _DATA_DELIVERY_H

#include <stdint.h>

typedef enum _du_msg_type_t{
  TYPE_DEVICE_0,
  TYPE_DEVICE_1,
  TYPE_DEVICE_2,
  TYPE_DEVICE_3,
}du_msg_type_t;

#pragma pack(1)
typedef struct _du_samp_package_header_t{
  uint8_t type;
  uint32_t size;
  uint8_t align[3];
  uint8_t body[];
}du_samp_package_header_t;
#pragma pack()

#endif
