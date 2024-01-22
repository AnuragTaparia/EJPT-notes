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
- 