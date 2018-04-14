#ifndef EVALUATION_H
#define EVALUATION_H

typedef struct _file_t {
  uint8_t payload_size;
  uint8_t offset[7];
  uint8_t payload_tag[16];
  uint8_t payload[8];
} enc_file;

#endif
