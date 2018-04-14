#include <stdio.h>
#include <memory.h>
#include <stdlib.h>


#include "data_sample.h"
#include "sample_dev_data.h"


int data_send(uint8_t dev_id, uint8_t offset, sp_samp_dev_data_t **pp_dev_data){
  sp_samp_dev_data_t *dev_data = NULL;

  dev_data = (sp_samp_dev_data_t *)malloc(sizeof(sp_samp_dev_data_t) + DATA_SIZE);
  if(NULL == dev_data){
    fprintf(stderr, "\nError, out of memory in [%s].", __FUNCTION__);
    return -1;
  }
  memset(dev_data, 0, sizeof(sp_samp_dev_data_t) + DATA_SIZE);

  dev_data->size = DATA_SIZE;

  if(0 == dev_id){
    if(0 == offset){
      memcpy(dev_data->data, &dev_0_data_sample_0[0], sizeof(dev_0_data_sample_0));
    }else if(1 == offset){
      memcpy(dev_data->data, &dev_0_data_sample_1[0], sizeof(dev_0_data_sample_0));
    }else if(2 == offset){
      memcpy(dev_data->data, &dev_0_data_sample_2[0], sizeof(dev_0_data_sample_0));
    }
  }

  *pp_dev_data = dev_data;

  return 0;
}
