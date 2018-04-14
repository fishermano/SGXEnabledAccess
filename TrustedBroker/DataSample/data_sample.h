#ifndef DATA_SAMPLE
#define DATA_SAMPLE

#include <stdint.h>

#define DATA_SIZE 8

typedef struct _sp_samp_dev_data_t{
  uint8_t size;
  uint8_t data[];
}sp_samp_dev_data_t;

int data_send(uint8_t dev_id, uint8_t offset, sp_samp_dev_data_t **pp_dev_data);

#endif
