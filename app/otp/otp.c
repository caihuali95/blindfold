#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "hmac-sha1.h"

#define SHA1_DIGEST_LENGTH 20

int genCode() {
    uint8_t challenge[8];
    uint8_t resultFull[SHA1_DIGEST_LENGTH];
    uint8_t key[] = {0x72, 0x0C, 0x38, 0x4D, 0x6B, 0x50, 0x63, 0xA7, 0xD8, 0x7E};
    unsigned int truncatedHash = 0;
    int offset = 0;

    uint64_t tm = time(NULL) / 30;
    for (int i = 8; i--; tm >>= 8) challenge[i] = tm;

    hmac_sha1(resultFull, key, sizeof(key) * 8, challenge, sizeof(challenge) * 8);
    offset = resultFull[SHA1_DIGEST_LENGTH - 1] & 0xF;

    for (int i = 0; i < 4; ++i) {
        truncatedHash <<= 8;
        truncatedHash  |= resultFull[offset + i];
    }
    truncatedHash &= 0x7FFFFFFF;
    truncatedHash %= 1000000;

    return truncatedHash;
}

void run(int ROUNDS) {
    unsigned char byte = (unsigned char)'O';
    if (ROUNDS == 0) {
        fprintf(stdout, "OTP = %u\n", genCode());       // print to screen
        return;
    }
    write(STDOUT_FILENO, &byte, sizeof(byte));          // for evaluation with test_app.py
    while (ROUNDS--) {
        read(STDIN_FILENO, &byte, sizeof(byte));
        genCode();
        write(STDOUT_FILENO, &byte, sizeof(byte));
    }
}

int main(int argc, char **argv) {
    int ROUNDS = 0;
    if (argc >= 3 && strcmp(argv[argc - 2], "-r") == 0)
        ROUNDS = strtol(argv[argc - 1], NULL, 0);
    run(ROUNDS);
    return 0;
}
