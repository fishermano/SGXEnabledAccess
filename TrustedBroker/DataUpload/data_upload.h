
#ifndef _DATA_UPLOAD_H
#define _DATA_UPLOAD_H

#include "data_delivery.h"

int sp_upload_data(const char *cloud_storage_url, uint8_t dev_id, uint8_t offset, du_samp_package_header_t **response);

#endif
