# oblique 2010

.text
.globl _start
_start:
# mmap2(NULL, shellcode len + 0x2000, PROT_EXEC|PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    xorl %ebx, %ebx     # addr = 0
    movl $0xfee1dead, %ecx
    addl $0x2000, %ecx  # length
    movl $0x7, %edx     # prot = PROT_EXEC | PROT_WRITE | PROT_READ
    movl $0x22, %esi    # flags = MAP_PRIVATE | MAP_ANONYMOUS
    movl $-1, %edi      # fd = -1
    xorl %ebp, %ebp     # pgoffset = 0
    movl $192, %eax     # mmap syscall number
    int $0x80
    
# copy shellcode to memory
    jmp getshellcodeaddr # trick to get the shellcode address
back:
    popl %ebx           # save the shellcode address to ebx
    xorl %ecx, %ecx
    movl $0xfee1dead, %esi
copy:
    movb (%ebx, %ecx), %dl
    movb %dl, (%eax, %ecx)
    inc %ecx
    cmpl %esi, %ecx
    jne copy

# clone(%eax + shellcode len + 0x2000 - 4, CLONE_VM|CLONE_SIGHAND|CLONE_THREAD, NULL, NULL, NULL)
    movl %eax, %ecx     # child_stack = %eax + shellcode len + 0x2000 - 4
    addl $0xfee1dead, %ecx
    addl $(0x2000-4), %ecx
    movl %eax, (%ecx)
    movl $0x10900, %ebx # flags = CLONE_VM | CLONE_THREAD | CLONE_SIGHAND
    xorl %edx, %edx     # ptid = NULL
    xorl %esi, %esi     # tls = NULL
    xorl %edi, %edi     # ctid = NULL
    movl $120, %eax     # clone syscall number
    int $0x80

    cmpl $0, %eax
    je child        # the child will continue

    int $3      # the parrent will return to the injector

child:
    popl %eax
    jmpl *%eax

getshellcodeaddr:
    call back
shellcode:
