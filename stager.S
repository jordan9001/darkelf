BITS 64

DEFAULT REL

; to use this code,  you need to place some things at the end
; an 8byte return address to the real main
; a null terminated libpath
; a null terminated export to call

	jmp PING
PONG:
	pop rax
	push [rax] ; push our return address
	
	;save state for real main
	push rdi
	push rsi
	push rdx
	
	;TODO
	
	; return to the real main
	pop rdx
	pop rsi
	pop rdi
	ret
	
PING:
	call PONG	

