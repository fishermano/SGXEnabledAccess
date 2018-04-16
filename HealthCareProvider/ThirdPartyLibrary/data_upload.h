
#ifndef _DATA_UPLOAD_H
#define _DATA_UPLOAD_H

#include "network.h"

int sp_upload_data(const char *cloud_storage_url, uint8_t dev_id, uint8_t offset, pkg_header_t **response);

#endif
