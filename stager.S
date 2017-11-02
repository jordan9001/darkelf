.section .text
.intel_syntax noprefix

# exported symbols
.globl SH_CODE_START, SH_CODE_END

# can't import symbols, because we need offset independant stuff

# to use this code,  you need to place some things at the end
# an 8byte return address to the real main
# a null terminated libpath
# a null terminated export to call

SH_CODE_START:
	jmp PING
PONG:
	pop rcx
	push [rcx] # push our return address
	
	# save state for real main
	push rdi
	push rsi
	push rdx

	# call dlopen
	mov rbx, [rcx + 0x10]
	lea rdi, [rcx + 0x18]

	push rcx
	
	# rbx is a pointer to the function pointer
	# or a got entry for the function pointer
	mov rbx, [rbx]
	call rbx
	pop rcx

	mov rdi, rax
	# go till past null to get to the func name
	lea rsi, [rcx + 0x18]
STRLOOP:
	inc rsi
	mov rbx, [rsi]
	test rbx, rbx
	jne STRLOOP
	inc rsi

	lea rbx, [rcx + 0x08]
	mov rbx, [rbx]
	call rbx
	call rax
	
	# return to the real main
	pop rdx
	pop rsi
	pop rdi
	ret
	
PING:
	call PONG	


SH_CODE_END:
	# real main addr
	# dlsym
	# dopen
	# lib 0x00 func 0x00
