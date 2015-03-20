// re-enable injectStringGated
#include "lsym.h"
lsym_map_t *lsym_map_file_writable(const char *path) {
    int fd=open(path, O_RDWR);
    struct stat sb;
    fstat(fd, &sb);
    void* map = mmap(NULL, sb.st_size  & 0xFFFFFFFF, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    lsym_map_t* ret = (lsym_map_t*)malloc(sizeof(lsym_map_t));
    ret->map  = map;
    ret->path = path;
    ret->sz = sb.st_size & 0xFFFFFFFF;
    return ret;
}

int main() {
    if (getuid()) {
        printf("run as root\n");
        return 1;
    }
    lsym_map_t* mapping = lsym_map_file_writable("/System/Library/Extensions/IOHIDFamily.kext/Contents/MacOS/IOHIDFamily");
    uint8_t* vuln = ((uint8_t*)mapping->map + lsym_find_symbol(mapping, "__ZN23IOHIDSecurePromptClient17injectStringGatedEPvS0_S0_S0_"));
    if(vuln == mapping->map) {printf("missing function, is your OS >10.10.2? cannot unpatch\n");}
    if (*vuln == 0x55) {
        printf("not patched!\n");
        return 0;
    }
    printf("patched \\x%x to \\x55 at offset 0x%p\n", *vuln, (void*)((uint64_t) vuln - (uint64_t)mapping->map));
    *vuln = 0x55;
}
