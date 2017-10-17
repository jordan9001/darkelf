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
	pop rax
	push [rax] # push our return address
	
	# save state for real main
	push rdi
	push rsi
	push rdx

	
	
	# TODO
	
	# return to the real main
	pop rdx
	pop rsi
	pop rdi
	ret
	
PING:
	call PONG	


SH_CODE_END:
