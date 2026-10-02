/*
 * Linux user-space example for hmac_avmm on the DE10-Nano.
 *
 * Maps the lightweight HPS-to-FPGA bridge through /dev/mem (needs root), loads
 * a key once and computes HMAC-SHA256 for a few messages.  HMAC_OFFSET is the
 * base address Platform Designer assigned to the component on the bridge.
 *
 * Build on the board:  gcc -O2 -Wall -o hmac_example hmac_example.c
 * Run:                 sudo ./hmac_example
 *
 * For production use, restrict access with a UIO driver instead of /dev/mem:
 * whoever can reach these registers can use the stored key.
 */

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define LW_BRIDGE_BASE 0xFF200000u
#define LW_BRIDGE_SPAN 0x00200000u
#ifndef HMAC_OFFSET
#define HMAC_OFFSET    0x00000000u
#endif

/* register byte offsets (see src/hmac_avmm.v) */
#define REG_CTRL    0x00
#define REG_STATUS  0x04
#define REG_MSG_LEN 0x08
#define REG_ID      0x0C
#define REG_KEY     0x20
#define REG_MSG     0x40
#define REG_MAC     0x80

#define CTRL_START      (1u << 0)
#define CTRL_CLEAR_KEY  (1u << 1)
#define CTRL_CLEAR_DATA (1u << 2)

#define ST_READY      (1u << 0)
#define ST_DONE       (1u << 1)
#define ST_ERR        (1u << 2)
#define ST_KEY_LOADED (1u << 3)

#define HMAC_ID      0x484D4143u
#define MAX_MSG      55

static volatile uint32_t *regs;

static void wr(unsigned off, uint32_t v) { regs[off / 4] = v; }
static uint32_t rd(unsigned off) { return regs[off / 4]; }

/* copy bytes into consecutive registers, 4 bytes per word, little-endian */
static void wr_bytes(unsigned off, const uint8_t *src, size_t len, size_t words)
{
    for (size_t i = 0; i < words; i++) {
        uint8_t b[4] = {0, 0, 0, 0};
        for (size_t j = 0; j < 4 && 4 * i + j < len; j++)
            b[j] = src[4 * i + j];
        wr(off + 4 * i, (uint32_t)b[0] | (uint32_t)b[1] << 8 |
                        (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24);
    }
}

static int hmac_load_key(const uint8_t key[32])
{
    if (!(rd(REG_STATUS) & ST_READY))
        return -1;
    wr_bytes(REG_KEY, key, 32, 8);
    return 0;
}

static int hmac_compute(const uint8_t *msg, size_t len, uint8_t mac[32])
{
    if (len > MAX_MSG)
        return -1;
    while (!(rd(REG_STATUS) & ST_READY))
        ;
    wr_bytes(REG_MSG, msg, len, 14);
    wr(REG_MSG_LEN, (uint32_t)len);
    wr(REG_CTRL, CTRL_START);

    uint32_t st;
    while (!((st = rd(REG_STATUS)) & (ST_DONE | ST_ERR)))
        ;
    if (st & ST_ERR)
        return -1;
    for (int i = 0; i < 8; i++) {
        uint32_t w = rd(REG_MAC + 4 * i);
        mac[4 * i + 0] = w & 0xff;
        mac[4 * i + 1] = (w >> 8) & 0xff;
        mac[4 * i + 2] = (w >> 16) & 0xff;
        mac[4 * i + 3] = (w >> 24) & 0xff;
    }
    return 0;
}

static void hmac_clear_key(void)
{
    wr(REG_CTRL, CTRL_CLEAR_KEY | CTRL_CLEAR_DATA);
}

int main(void)
{
    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        perror("open /dev/mem");
        return 1;
    }
    void *base = mmap(NULL, LW_BRIDGE_SPAN, PROT_READ | PROT_WRITE, MAP_SHARED,
                      fd, LW_BRIDGE_BASE);
    if (base == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }
    regs = (volatile uint32_t *)((uint8_t *)base + HMAC_OFFSET);

    if (rd(REG_ID) != HMAC_ID) {
        fprintf(stderr, "no hmac_avmm at offset 0x%x (ID 0x%08x)\n",
                HMAC_OFFSET, rd(REG_ID));
        return 1;
    }

    /* RFC 4231 test case 2: key "Jefe", zero-padded to 32 bytes */
    uint8_t key[32] = {'J', 'e', 'f', 'e'};
    const char *msg = "what do ya want for nothing?";
    uint8_t mac[32];

    hmac_load_key(key);
    memset(key, 0, sizeof key);          /* the FPGA keeps its own copy */

    if (hmac_compute((const uint8_t *)msg, strlen(msg), mac) != 0) {
        fprintf(stderr, "HMAC failed\n");
        return 1;
    }
    printf("HMAC: ");
    for (int i = 0; i < 32; i++)
        printf("%02x", mac[i]);
    printf("\nexpected 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843\n");

    hmac_clear_key();
    munmap(base, LW_BRIDGE_SPAN);
    close(fd);
    return 0;
}
