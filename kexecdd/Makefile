all: exploit.exe exploit.dll restore.dll

exploit.exe:
	cl.exe /nologo /MT /Ox /W0 /GS- /DNDEBUG loader.c /link Advapi32.lib /OUT:exploit.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
	move exploit.exe ..\bin\exploit.exe

exploit.dll:
	cl.exe /LD /nologo /MT /Ox /W0 /GS- /DNDEBUG dllmain.c /link /OUT:exploit.dll /SUBSYSTEM:CONSOLE /MACHINE:x64
	move exploit.dll ..\bin\exploit.dll

restore.dll:
	cl.exe /LD /nologo /MT /Ox /W0 /GS- /DNDEBUG dllmain_restore.c /link /OUT:restore.dll /SUBSYSTEM:CONSOLE /MACHINE:x64
	move restore.dll ..\bin\restore.dll




clean:
	del *.obj
	del ..\bin\exploit.dll ..\bin\restore.dll ..\bin\exploit.exe