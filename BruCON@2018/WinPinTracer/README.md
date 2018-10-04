Intel Pin tool to monitor program execution traces! 

Inspired and derived from -> https://github.com/SideChannelMarvels/Tracer/tree/master/TracerPIN

Modifications:
  - refactoring to remove database dump to keep code clean and minimal, only text entries
  - filtering approach
  - support for module based filtering, default is to main executable module 
  - support for range of offsets for filtering in case if you want to monitor for specific basic blocks or functions
  - added context dump on basic blocks and instructions 
  - script to parse logs in order to process it in python? may feed it to external cancolic execution framework like triton!
  
example trace of a program - 

[M] ModuleLoad C:\Users\JohnDoe\Desktop\foo\read.exe 000000e00000-000000e34fff
[M] ModuleLoad C:\Windows\syswow64\kernel32.dll 000076680000-00007678ffff
[M] ModuleLoad C:\Windows\syswow64\KERNELBASE.dll 000077580000-0000775c5fff
[M] ModuleLoad C:\Windows\SysWOW64\ntdll.dll 000077ba0000-000077d1ffff
[T]	THREAD STARTED 0x00000000 flags: 0x00000001

[B] 00000000 0000000000e01ffb mainCRTStartup: // size=5 // eax=00000000766933b8 ebx=000000007efde000 ecx=0000000000000000 edx=0000000000e01ffb edi=0000000000000000 esi=0000000000000000 eip=0000000000e01ffb esp=000000000015fd34 ebp=000000000015fd3c eflags=0000000000000246 fs=0000000000000053 gs=000000000000002b eflags=0000000000000246 
[I]	00000000 0000000000e01ffb e8 95 57 00 00                           call 0xe07795                                      
[C]	00000000 0000000000e01ffb call 0000000000e07795 (__security_init_cookie) (000000007efde000, 000000000015fd7c, 0000000077bd9ed2)
[W] 00000000 0000000000e01ffb	                                                                                            addr=000000000015fd30 size=00000004 value=0000000000e02000

[B] 00000000 0000000000e07795 __security_init_cookie: // size=35 // eax=00000000766933b8 ebx=000000007efde000 ecx=0000000000000000 edx=0000000000e01ffb edi=0000000000000000 esi=0000000000000000 eip=0000000000e07795 esp=000000000015fd30 ebp=000000000015fd3c eflags=0000000000000246 fs=0000000000000053 gs=000000000000002b eflags=0000000000000246 
[I]	00000000 0000000000e07795 55                                       push ebp                                           ebp=000000000015fd3c eflags=0000000000000246 
[W] 00000000 0000000000e07795	                                                                                            addr=000000000015fd2c size=00000004 value=000000000015fd3c
[I]	00000000 0000000000e07796 8b ec                                    mov ebp, esp                                       esp=000000000015fd2c ebp=000000000015fd3c eflags=0000000000000246 
[I]	00000000 0000000000e07798 83 ec 14                                 sub esp, 0x14                                      esp=000000000015fd2c eflags=0000000000000246 
[R] 00000000 0000000000e0779b	                                                                                            addr=000000000015fd20 size=00000004 value=0000000000000000
[I]	00000000 0000000000e0779b 83 65 f4 00                              and dword ptr [ebp-0xc], 0x0                       ebp=000000000015fd2c eflags=0000000000000206 
[W] 00000000 0000000000e0779b	                                                                                            addr=000000000015fd20 size=00000004 value=0000000000000000