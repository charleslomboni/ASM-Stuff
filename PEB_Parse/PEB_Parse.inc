;include inclui arquivos com extenção .asm e .inc
;includelib inclui bibliotecas .lib

include windows.inc			;inclui a biblioteca de apis do windows
include user32.inc			;inclui a biblioteca user32.dll
include kernel32.inc		;inclui a biblioteca kernel32.dll

includelib user32.lib	
includelib kernel32.lib

BeingDebugged		PROTO
Ldr					PROTO
GetFunctionAddress	PROTO

.data
;---------------- BeingDebugged
dbgNoActiveText			db	"No debug found!",0
dbgNoActiveCaption		db	"NICE!",0

dbgActiveText			db	"Oops... debug found!",0
dbgActiveCaption		db	"CATCHED!",0

;----------------- Ldr
szUser32            	byte  	"User32.dll",0
api_MessageBoxA        	byte  	"MessageBoxA",0
api_GetProcAddress     	byte  	"GetProcAddress",0
api_LoadLibrary			byte	"LoadLibraryA",0
szTitle              	byte  	"Yo !",0
szMsg              		byte  	"GreeTz From SIGSEGV",0

.data?
AGetProcAddressA       	dword  0
len_GetProcAddress     	dword  0
ALoadLibraryA          	dword  0
AMessageBoxAA          	dword  0
dwKernelBase           	dword  0
dwExportDirectory      	dword  0