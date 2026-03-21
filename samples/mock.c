#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <time.h>

/* --------- Fragmented Crypto Artifact --------- */
static const unsigned char sbox_frag_a[] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5
};
static const unsigned char sbox_frag_b[] = {
    0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76
};

/* --------- Lightweight Stream Transform --------- */
void transform(uint8_t *buf, size_t len, uint8_t k) {
    for (size_t i = 0; i < len; i++)
        buf[i] = (buf[i] + 1) ^ k;
}

/* --------- Encoded Configuration --------- */
uint8_t config_blob[] = {
    0x35,0x3a,0x35,0x3e,0x2f,0x3b,0x30,0x77,
    0x77,0x39,0x35,0x3d,0x77,0x32,0x3b
};

/* --------- Environment Fingerprint --------- */
int fingerprint() {
    int score = 0;
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "TracerPid") && !strstr(line, "0"))
                score++;
        }
        fclose(f);
    }
    if (access("/.dockerenv", F_OK) == 0)
        score++;
    return score;
}

/* --------- Indirect Dispatch --------- */
typedef void (*stage_fn)();

void stage_init() {
    printf("[s] init\n");
}

void stage_process() {
    printf("[s] process\n");
}

void stage_finalize() {
    printf("[s] finalize\n");
}

/* --------- Dynamic Symbol Resolution --------- */
void dynamic_call() {
    void *lib = dlopen("libc.so.6", RTLD_LAZY);
    if (!lib) return;

    int (*dyn_printf)(const char*, ...) =
        dlsym(lib, "printf");

    if (dyn_printf)
        dyn_printf("[dyn] symbol resolved\n");

    dlclose(lib);
}

/* --------- Memory Mutation Simulation --------- */
void memory_sim() {
    void *mem = mmap(NULL, 4096,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);

    if (!mem) return;

    memset(mem, 0x41, 4096);

    for (int i = 0; i < 4096; i++)
        ((uint8_t*)mem)[i] ^= (i % 255);

    mprotect(mem, 4096, PROT_READ);

    munmap(mem, 4096);
}

/* --------- State Machine --------- */
void execute_flow() {
    stage_fn table[] = {
        stage_init,
        stage_process,
        stage_finalize
    };

    for (int i = 0; i < 3; i++)
        table[i]();
}

int main() {

    srand(time(NULL));

    int env = fingerprint();
    if (env > 0)
        sleep(1);

    transform(config_blob, sizeof(config_blob), 0x5A);
    printf("[cfg] %s\n", config_blob);

    execute_flow();
    dynamic_call();
    memory_sim();

    printf("[done]\n");
    return 0;
}