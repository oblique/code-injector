# oblique 2010

.text
.globl _start
_start:
# mmap(NULL, shellcode len + 0x2000, PROT_EXEC|PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    xorq %rdi, %rdi     # addr = 0
    xorq %rsi, %rsi
    movq $0xfee1dead, %rsi
    addq $0x2000, %rsi  # length = shellcode len + 0x2000
    movq $0x7, %rdx     # prot = PROT_EXEC | PROT_WRITE | PROT_READ
    movq $0x22, %r10    # flags = MAP_PRIVATE | MAP_ANONYMOUS
    movq $-1, %r8       # fd = -1
    xorq %r9, %r9       # pgoffset = 0
    movq $9, %rax       # mmap syscall number
    syscall

# copy shellcode to memory
    jmp getshellcodeaddr
back:
    popq %rbx
    xorq %rcx, %rcx
    xorq %r8, %r8
    movq $0xfee1dead, %r8
copy:
    movb (%rbx, %rcx), %dl
    movb %dl, (%rax, %rcx)
    inc %rcx
    cmpq %r8, %rcx
    jne copy

# clone(%eax + shellcode len + 0x2000 - 8, CLONE_VM|CLONE_SIGHAND|CLONE_THREAD, NULL, NULL, NULL)
    movq %rax, %rsi     # child_stack = %rax + shellcode len + 0x2000 - 8
    movq $0xfee1dead, %r8
    addq %r8, %rsi
    addq $(0x2000-8), %rsi
    movq %rax, (%rsi)
    movq $0x10900, %rdi # flags = CLONE_VM | CLONE_SIGHAND | CLONE_THREAD
    xorq %rdx, %rdx     # ptid = NULL
    xorq %r8, %r8       # tls = NULL
    xorq %r10, %r10     # ctid = NULL
    movq $56, %rax      # close syscall number
    syscall

    cmpq $0, %rax
    je child            # child will continue

    int3                # parrent will return to the injector

child:
    popq %rax
    jmpq *%rax

getshellcodeaddr:
    call back
shellcode:
