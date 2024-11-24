#include "kernel/types.h"
#include "user/user.h"
#include <stddef.h>

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

#define ROTRIGHT(word, bits) (((word) >> (bits)) | ((word) << (32 - (bits))))
#define SSIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SSIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Initialize SHA-256 hash values
void sha256_init(uint32_t *state) {
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
}

void sha256_transform(uint32_t *state, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    // Prepare message schedule
    for (i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | data[j + 3];
    }
    for (; i < 64; ++i) {
        m[i] = SSIG1(m[i - 2]) + m[i - 7] + SSIG0(m[i - 15]) + m[i - 16];
    }

    // Initialize working variables
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    // Main loop
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Update hash values
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256_update(uint32_t *state, const uint8_t data[], size_t len, uint8_t *buffer, size_t *buffer_len, uint64_t *bit_len) {
    size_t i;

    // Process the data in blocks
    for (i = 0; i < len; ++i) {
        buffer[(*buffer_len)++] = data[i];
        *bit_len += 8;

        if (*buffer_len == 64) {
            sha256_transform(state, buffer);
            *buffer_len = 0;
        }
    }
}

void sha256_final(uint32_t *state, uint8_t hash[], uint8_t *buffer, size_t buffer_len, uint64_t bit_len) {
    buffer[buffer_len++] = 0x80;

    if (buffer_len > 56) {
        while (buffer_len < 64) buffer[buffer_len++] = 0x00;
        sha256_transform(state, buffer);
        buffer_len = 0;
    }
    while (buffer_len < 56) buffer[buffer_len++] = 0x00;

    // Append the length of the message
    for (int i = 0; i < 8; ++i) {
        buffer[63 - i] = (bit_len >> (8 * i)) & 0xff;
    }

    sha256_transform(state, buffer);

    // Copy the hash to the output
    for (int i = 0; i < 8; ++i) {
        hash[i * 4] = (state[i] >> 24) & 0xff;
        hash[i * 4 + 1] = (state[i] >> 16) & 0xff;
        hash[i * 4 + 2] = (state[i] >> 8) & 0xff;
        hash[i * 4 + 3] = state[i] & 0xff;
    }
}

void sha256_user(const uint8_t *data, size_t len, uint8_t hash[]) {
    uint32_t state[8];
    uint8_t buffer[64];
    size_t buffer_len = 0;
    uint64_t bit_len = 0;

    sha256_init(state);
    sha256_update(state, data, len, buffer, &buffer_len, &bit_len);
    sha256_final(state, hash, buffer, buffer_len, bit_len);
}

void print_hashcode(uint8_t *hash) {
    const char *hex_digits = "0123456789abcdef";
    char hash_string[65];
    for (int i = 0; i < 32; i++) {
        hash_string[i * 2] = hex_digits[(hash[i] >> 4) & 0xF];
        hash_string[i * 2 + 1] = hex_digits[hash[i] & 0xF];
    }
    hash_string[64] = '\0';
    printf("%s\n", hash_string);
}

int main(int argc, char *argv[]) {
    uint8_t hash[32];

    if (argc < 2) {
        printf("Usage: %s <string>\n", argv[0]);
        exit(1);
    }
    int total_length = 0;
    for (int i = 1; i < argc; i++) {
        for (int j = 0; argv[i][j] != '\0'; j++) {
            total_length++;
        }
        if (i < argc - 1) {
            total_length++;
        }
    }

    // Allocate memory to store the concatenated input
    char combined_input[total_length + 1];
    int length = 0;

    // Concatenate all arguments with spaces in between
    for (int i = 1; i < argc; i++) {
        for (int j = 0; argv[i][j] != '\0'; j++) {
            combined_input[length++] = argv[i][j];
        }
        if (i < argc - 1) {
            combined_input[length++] = ' ';
        }
    }
    combined_input[length] = '\0';


    int start = gettime()/10000;
    printf("time start:%d\n",start);
    sha256_user((const uint8_t*)combined_input, length, hash);
    int end = gettime()/10000;

    printf("Hash Code for %s\n", combined_input);
    print_hashcode(hash);
    printf("\n");
    printf("time end:%d\n",end);
    printf("Total Time Taken in milliseconds: %d\n", end-start);

    exit(0);
}
