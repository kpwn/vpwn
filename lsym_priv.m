#import "lsym_priv.h"
#include <Foundation/Foundation.h>

/*
 returns kernel base on the local system
 */

extern CFDictionaryRef OSKextCopyLoadedKextInfo(CFArrayRef, CFArrayRef);

uint64_t lsym_find_base() {
    // KASLR break
return 0;
}

/*
 data: data to write past zone slice boundaries.
 size: size of data
 
 returns 0 on failure
 */
char lsym_heap_overflow(char* data, size_t size) {
#error No exploit is bundled with this software. This is merely a PoC for generic heap overflow exploitation on XNU. Please add your own vulnerability here.
    // Heap Overflow
    return 0;
}

uint64_t lsym_heap_overflow_bufsize() {
    return 512; // size of the overflown buffer
}
