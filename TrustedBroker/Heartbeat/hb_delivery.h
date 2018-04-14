#ifndef HB_DELIVERY
#define HB_DELIVERY

#include <stdint.h>

typedef enum _hb_msg_type_t{
  TYPE_HEARTBEAT,
}hb_msg_type_t;

#pragma pack(1)
typedef struct _hb_samp_package_header_t{
  uint8_t type;
  uint32_t size;
  uint8_t align[3];
  uint8_t body[];
}hb_samp_package_header_t;
#pragma pack()



#endif
