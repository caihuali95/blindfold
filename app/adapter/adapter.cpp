#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <elf.h>
#include "hmac-sha256.h"
using namespace std;

#define MULTIPLE    5
#define KEY_SIZE	16
#define HASH_SIZE	32
#define PAGE_SIZE	0x1000
#define BLOCK_SIZE	16
#define MAX_VADDR	0x8000000000

const unsigned char MAC_KEY[KEY_SIZE] = {0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
const unsigned char ENC_KEY[KEY_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
const int SEGMENT_ALIGNMENT = 0x10000;

Elf64_Ehdr *elfhdr;
Elf64_Off  *phdr_off;
Elf64_Half *phdr_num;
Elf64_Phdr *phdr, *text_phdr, *data_phdr;
Elf64_Shdr *text_shdr, *data_shdr;
int file_size, read_size, phdr_ent, phdr_siz, shim_text_siz, shim_data_siz;
long long lowest_va, highest_va;
char *buf, *elf;

extern void aes_hw_set_encrypt_key(unsigned char*, unsigned int, unsigned char*);
extern void aes_hw_encrypt(unsigned long long*, unsigned long long*, unsigned char*);

inline void print_error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}
inline int multiply_file_size(int size) {
    return (size + PAGE_SIZE) * MULTIPLE;
}
template <class T> void alignment(T& data, int align) {
    if (data % align) data += align - data % align;
}

void readfile(int argc, char* argv[]) {                                 // read target ELF file into buf
    if (argc <= 1) print_error("usuage: ./adapter <ELF file path>");
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) print_error("fail to open file");
    fseek(fp, 0, SEEK_END);                                             // get file size
    file_size = ftell(fp);
    rewind(fp);
    buf = (char*)calloc(multiply_file_size(file_size), sizeof(char));   // allocate more memory than the file size
    if (!buf) print_error("fail to allocate memory");                   // to avoid buffer overflow
    read_size = fread(buf, 1, file_size, fp);                           // read the ELF file into the buffer
    if (read_size != file_size) print_error("fail to read binary");
    fclose(fp);
}

void insert_section_header(int &cur_size) {
    Elf64_Off  *shdr_off = &elfhdr->e_shoff;
    Elf64_Half *shdr_num = &elfhdr->e_shnum;
    Elf64_Half *shdr_ent = &elfhdr->e_shentsize;
    int         shdr_siz = ((int)*shdr_num) * ((int)*shdr_ent);
    assert(read_size == *shdr_off + shdr_siz);
    assert(read_size == cur_size);
    text_shdr = (Elf64_Shdr*)(elf + cur_size);
    cur_size += (int)*shdr_ent;
    ++(*shdr_num);
    data_shdr = (Elf64_Shdr*)(elf + cur_size);
    cur_size += (int)*shdr_ent;
    ++(*shdr_num);
}

void update_phdr_meta(Elf64_Phdr* phdr, int phdr_num, unsigned long current) {
    for (int i = 0; i < phdr_num; ++i)
        if (phdr[i].p_type == PT_PHDR) {
            phdr[i].p_offset = current;
            phdr[i].p_vaddr = current;
        }
}

void update_phdr(Elf64_Phdr *phdr, Elf64_Word flags, Elf64_Xword fsz, Elf64_Xword msz, int &cur_size) {
    phdr->p_type   = 0x1;
    phdr->p_flags  = flags;
    phdr->p_vaddr  = highest_va;
    phdr->p_paddr  = highest_va;
    phdr->p_filesz = fsz;
    phdr->p_memsz  = msz;
    phdr->p_align  = SEGMENT_ALIGNMENT;
    highest_va += phdr->p_memsz;
    cur_size += phdr->p_filesz;
}

void hashmac(char *buf, int l, int h, char *mac) {
    hmac_sha256((void *)mac, (const void *)MAC_KEY, KEY_SIZE * 8, (const void *)(buf + l), (h - l) * 8);
}

void create_readonly(int &cur_size, int phdr_siz) {
    unsigned long off, len;
    shim_text_siz = PAGE_SIZE - HASH_SIZE;
    *(long long*)(elf + cur_size + shim_text_siz - 8) = *phdr_num;
    *(long long*)(elf + cur_size + shim_text_siz - 16) = lowest_va;
    update_phdr(text_phdr, 0x4, PAGE_SIZE, PAGE_SIZE, cur_size);
    off = text_phdr->p_offset;
    len = PAGE_SIZE - HASH_SIZE;
    hashmac(elf + off, 0, len, elf + off + len);
}

void encrypt(char *buf, int l, int h) {                                 // the encryption code does not work on RPI4
    assert((h - l) % BLOCK_SIZE == 0);                                  // due to lack of cryptography hardware extension
    unsigned char key[244];                                             // so we disable it on RPI4
    unsigned long long cipher[2];
//    aes_hw_set_encrypt_key(ENC_KEY, 128, key);
    for (int i = l; i < h; i += BLOCK_SIZE) {
//        aes_hw_encrypt((unsigned long long*)(buf + i), cipher, key);
//        memcpy(buf + i, cipher, BLOCK_SIZE);
    }
}

void create_readwrite(int &cur_size) {
    shim_data_siz = 0;
    for (int i = 0; i < *phdr_num - 2; ++i) {                           // store static signature
        if (phdr[i].p_type != 1) continue;
        long long off_f = phdr[i].p_offset;
        long long len_f = phdr[i].p_filesz;
        long long baddr = off_f / PAGE_SIZE * PAGE_SIZE + PAGE_SIZE;
        long long low_va = phdr[i].p_vaddr / PAGE_SIZE * PAGE_SIZE + PAGE_SIZE;
        long long offset = (low_va - lowest_va) / PAGE_SIZE * HASH_SIZE;
        for (; baddr + PAGE_SIZE <= off_f + len_f; baddr += PAGE_SIZE) {
            encrypt(elf + baddr, 0, PAGE_SIZE);
            hashmac(elf + baddr, 0, PAGE_SIZE, elf + cur_size + offset);
            offset += HASH_SIZE;
        }
        if (offset > shim_data_siz) shim_data_siz = offset;
    }
    long long tmp = (MAX_VADDR - lowest_va) / PAGE_SIZE * HASH_SIZE;    // length of dynamic signature
    update_phdr(data_phdr, 0x6, shim_data_siz, tmp, cur_size);
}

void update_shdr() {
    text_shdr->sh_type      = SHT_PROGBITS;
    text_shdr->sh_flags     = 0x2;
    text_shdr->sh_addr      = text_phdr->p_vaddr;
    text_shdr->sh_offset    = text_phdr->p_offset;
    text_shdr->sh_size      = text_phdr->p_filesz;
    text_shdr->sh_link      = SHN_UNDEF;
    text_shdr->sh_info      = 0;
    text_shdr->sh_addralign = 0x8;
    text_shdr->sh_entsize   = 0;
    data_shdr->sh_type      = SHT_PROGBITS;
    data_shdr->sh_flags     = 0x3;
    data_shdr->sh_addr      = data_phdr->p_vaddr;
    data_shdr->sh_offset    = data_phdr->p_offset;
    data_shdr->sh_size      = data_phdr->p_filesz;
    data_shdr->sh_link      = SHN_UNDEF;
    data_shdr->sh_info      = 0;
    data_shdr->sh_addralign = 0x8;
    data_shdr->sh_entsize   = 0;
}

void instrument_binary() {
    elfhdr = (Elf64_Ehdr*)buf;
    phdr = (Elf64_Phdr*)(buf + elfhdr->e_phoff);
    lowest_va = MAX_VADDR;
    highest_va = 0;
    for (int i = 0; i < elfhdr->e_phnum; ++i)
        if (phdr[i].p_type == PT_LOAD) {                    // loadable segment
            lowest_va = min(lowest_va, (long long)phdr[i].p_vaddr);
            highest_va = max(highest_va, (long long)(phdr[i].p_vaddr + phdr[i].p_memsz));
        }
    file_size = multiply_file_size(max(highest_va - lowest_va, (long long)read_size));
    elf = (char*)calloc(file_size, sizeof(char));           // allocate output buffer for the adapted file
    if (!elf) print_error("fail to allocate memory");
    memcpy(elf, buf, read_size);                            // copy the original file to the output elf buffer
    elfhdr = (Elf64_Ehdr*)elf;
    memcpy(elfhdr->e_ident + 0x8, "Hongsen\0", 0x8);        // append "Hongsen" to the ELF magic number
    phdr_off = &elfhdr->e_phoff;
    phdr_num = &elfhdr->e_phnum;
    phdr_ent = (int)(elfhdr->e_phentsize);
    phdr_siz = ((int)*phdr_num) * phdr_ent;
    int cur_size = read_size;
    insert_section_header(cur_size);                        // insert section headers
    alignment(highest_va, SEGMENT_ALIGNMENT);               // new phdr at cur_size & highest_va
    while (cur_size > highest_va - lowest_va) highest_va += SEGMENT_ALIGNMENT;
    cur_size = highest_va - lowest_va;
    phdr = (Elf64_Phdr*)(elf + cur_size);                   // shim is a RO page for metadata
    memcpy(phdr, elf + *phdr_off, phdr_siz);                // copy the original program headers
    update_phdr_meta(phdr, *phdr_num, cur_size);
    *phdr_off = cur_size;
    text_phdr = (Elf64_Phdr*)(elf + *phdr_off + phdr_siz);  // append two program headers to the table
    data_phdr = (Elf64_Phdr*)(elf + *phdr_off + phdr_siz + phdr_ent);
    phdr_siz += 2 * phdr_ent;
    *phdr_num += 2;
    text_phdr->p_offset = cur_size;                         // create shim segment
    create_readonly(cur_size, phdr_siz);                    // metadata and its signature
    alignment(highest_va, SEGMENT_ALIGNMENT);
    alignment(cur_size, SEGMENT_ALIGNMENT);
    data_phdr->p_offset = cur_size;
    create_readwrite(cur_size);                             // signature & bss
    update_shdr();
    assert(cur_size <= file_size);
    file_size = cur_size;
    free(buf);
}

void writefile(char *argv) {
    string name = argv;
    name.insert(name.find_last_of("/") + 1, "adapted_");
    FILE *pFile = fopen(name.c_str(), "wb");
    fwrite(elf, 1, file_size, pFile);
    fclose(pFile);
    free(elf);
}

int main(int argc, char* argv[]) {
    readfile(argc, argv);
    instrument_binary();
    writefile(argv[1]);
    return 0;
}
