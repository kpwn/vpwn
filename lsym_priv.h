#include "lsym.h"
#include "import.h"

#ifndef __lsym_priv__
#define __lsym_priv__

/*
    returns kernel base on the local system
 */
uint64_t lsym_find_base();
#define FIND_KERNEL_SLIDE 0
//lsym_find_base()

/*
    data: data to write past heap boundaries
    size: size of data
 
    returns 0 on failure
 */
char lsym_heap_overflow(char* data, size_t size);

uint64_t lsym_heap_overflow_bufsize();


#endif
