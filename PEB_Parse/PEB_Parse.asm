.386					;tipo do processador 80386
.model flat,stdcall		;modelo de memoria 32bits
option casemap:none		;traz a sensibilidade de letras

include PEB_Parse.inc	;inclui o codigo do programa

.code

Start:
    assume fs:nothing

    INVOKE	BeingDebugged
    pushad
    INVOKE	Ldr
    INVOKE  ExitProcess,0
    
BeingDebugged PROC

	xor eax, eax				; Clear
	mov eax, fs:30h				; eax = _PEB
	cmp byte ptr [eax+2], 1 	; cmp if BeingDebugged is active
	
	je @active
	invoke MessageBox,NULL, addr dbgNoActiveText, addr dbgNoActiveCaption, MB_OK
    jmp @end
@active:
	invoke MessageBox,NULL, addr dbgActiveText, addr dbgActiveCaption, MB_ICONINFORMATION
@end:
    ret
BeingDebugged ENDP

Ldr PROC
	; Based on:
	; http://www.rohitab.com/discuss/topic/38717-quick-tutorial-finding-kernel32-base-and-walking-its-export-table/
	
	pop ebp
	sub ebp, Ldr						; Delta offset
	

	mov ebx, fs:30h						; PEB
	mov ebx, [ebx+0Ch]	 				; PEB->Ldr
	mov ebx, [ebx+14h]					; PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
	mov ebx, [ebx]     					; 2nd Entry
    mov ebx, [ebx]     					; 3rd Entry
    mov ebx, [ebx+10h]   				; Get Kernel32 Base
    mov [ebp+dwKernelBase] , ebx
    add ebx, [ebx+3Ch] 					; Start of PE header
    mov ebx, [ebx+78h] 					; RVA of export dir
    add ebx, [ebp+dwKernelBase] 		; VA of export dir
    mov [ebp+dwExportDirectory], ebx
    
    invoke lstrlen, offset api_GetProcAddress
    mov ecx, eax
    lea edx,[api_GetProcAddress]
    call GetFunctionAddress
    
    mov [AGetProcAddressA], eax
    lea edx, [api_LoadLibrary]
    
    push edx
    push [ebp+dwKernelBase]
    call eax
    
    mov [ALoadLibraryA], eax
    lea edx , [szUser32]
    push edx
    call eax
    
    lea edx , [api_MessageBoxA]
    push edx
    push eax
    mov ebx,[AGetProcAddressA]
    call ebx
    
    mov [AMessageBoxAA] , eax
    push 0
    lea edx,[szTitle]
    push edx
    lea edx,[szMsg]
    push edx
    push 0
    call eax
    
    popad
    push 0beefh   						;OEP
    retn
	
Ldr endp

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;     <<<<< GetFunctionAddress >>>>>>                                          ;
;    Extracts Function Address From Export Directory and returns it in eax      ;
;    Parameters :  Function name in edx , Length in ecx                       ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
 
GetFunctionAddress	PROC
	
    push ebx
    push esi
    push edi
 
    mov esi, [ebp+dwExportDirectory]
    mov esi, [esi+20h] 						; RVA of ENT
    add esi, [ebp+dwKernelBase]  			; VA of ENT
    xor ebx,ebx
    cld
 
    looper:
          inc ebx
          lodsd
          add eax , [ebp+dwKernelBase]  	; eax now points to the string of a function
          push esi      					; preserve it for the outer loop
          mov esi,eax
          mov edi,edx
          cld
          push ecx
          repe cmpsb
          pop ecx
          pop esi
          jne looper
 
          dec ebx
          mov eax,[ebp+dwExportDirectory]
          mov eax,[eax+24h]       			; RVA of EOT
          add eax,[ebp+dwKernelBase]     	; VA of EOT
          movzx eax, word ptr [ebx*2+eax]  	; eax now holds the ordinal of our function
          mov ebx,[ebp+dwExportDirectory]
          mov ebx,[ebx+1Ch]       			; RVA of EAT
          add ebx,[ebp+dwKernelBase]     	; VA of EAT
          mov ebx,[eax*4+ebx]
          add ebx,[ebp+dwKernelBase]
          mov eax,ebx
 
        pop edi
        pop esi
        pop ebx
        ret
        
GetFunctionAddress endp
end Start
