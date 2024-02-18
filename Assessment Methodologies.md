
# Information Gathering

###### Passive Information gathering
 - `host example.com` -- If got multiple IP that means there is a proxy
 - /robots.txt and /sitemap.xml
 - wappalyzer or `whatweb example.com`
 - `whois example.com/IP` 
 -  [dnsdumpster](https://dnsdumpster.com/) or `dnsrecon -d example.com`
 - `wafw00f example.com -a` -- for detecting firewall
 - `sublist3r -d example.com`
 - [wayback machine](https://web.archive.org/)
 - for [google dork](https://www.exploit-db.com/google-hacking-database)
 - [netcraft](https://www.netcraft.com/)

###### Active Information gathering
 - `dnsenum example.com` -- for zone transfer, or 
   `dig axfr @NS example.com` 
- `sudo nmap -sn 10.0.2.0/24` -- host discovery on the network
   `sudo arp-scan -l`
   `sudo netdiscover -i eth0 -r 10.0.2.0/24`
- `nmap -Pn -p- IP` -- for windows, if it if blocking ICMP
   `nmap -Pn -sU IP` -- for UDP
   `nmap -Pn -sV -p- IP` -- for service version detection
   `nmap -Pn -sV -O IP` -- for getting OS details (it may or may not be accurate)
   `nmap -Pn -sV -O -sC IP` -- it will run nmap scripts
   `nmap -Pn -A IP` -- it will give the combine output of the above nmap cmd
   `nmap -Pn -sV -O -T4 IP` -- It will speed up the process, you can adjust the time accordingly 
   `nmap -Pn -sV -O -T4 IP -oN test.txt` -- it will save the output of nmap, -oX for xml

---
---
# Footprinting & Scanning

###### Mapping a Network
 - `sudo arp-scan -g 10.11.11.0/24`
 - `fping -g 10.11.11.0/24 -a 2>/dev/null`
 - `nmap -sn 10.11.11.0/24`

---
---
# Enumeration

###### SMB(Server Message Block)
 - `nmap -T4 10.12.23.32/24  --open` -- looking for open ports
 - `net use Z: \\<IP>\C$ <Password> /user:<username>`  -- to mount drive using CMD
 - `nmap -T4 -p445 --script smb-protocols 10.12.23.4` -- 445 is smb port
 - `nmap -T4 -p445 --script smb-security-mode 10.12.23.4`
 - `nmap -T4 -p445 --script smb-enum-sessions 10.12.23.4`
 - `nmap -T4 -p445 --script smb-security-mode 10.12.23.4 --script-args smbusername=<USERNAME>,sbmpassword=<PASSWORD>`
 - `nmap -T4 -p445 --script smb-enum-shares 10.12.23.4` -- to enumerate shares
 - `nmap -T4 -p445 --script smb-enum-shares 10.12.23.4 --script-args smbusername=<USERNAME>,sbmpassword=<PASSWORD>`
 - `nmap -T4 -p445 --script smb-enum-users 10.12.23.4 --script-args smbusername=<USERNAME>,sbmpassword=<PASSWORD>` -- to enum users
 - `nmap -T4 -p445 --script smb-enum-groups 10.12.23.4 --script-args smbusername=<USERNAME>,sbmpassword=<PASSWORD>` -- to enum groups

- `smbmap -u <user> -p "<password>" -d . -H 10.12.26.14` -- used to connect 
	- if SMB v1 use `-u guest -p ""`
- `smbmap -u <user> -p "<password>" -d . -H 10.12.26.14 -x 'ipconfig' ` -- to run a cmd
- `smbmap -u <user> -p "<password>" -d . -H 10.12.26.14 -r C$` -- to give output as DIR
- `smbmap -u <user> -p "<password>" -d . -H 10.12.26.14 --upload '/path/to/file' '/path/to/upload'` -- to upload the file
- `smbmap -u <user> -p "<password>" -d . -H 10.12.26.14 --download '/path/to/file'` -- to upload the file
- `smbmap -u <USERNAME> -p "<PASSWORD>" -H 192.146.243.3` -- give which share is read only

- `nmap -T4 -p445 --script smb-os-discovery 10.12.23.4` -- discover the host os
- using msfconsole
	> msfconsole 
	> use auxiliary/scanner/smb/smb_version 
	> set RHOSTS 192.126.66.3 
	> exploit 

- `smbclient -L 10.12.23.4 -N` -- to check if null session
- `smbcient -L 10.12.23.4 -U <USERNAME/SHARENAME>` -- to check if share is browsable
- `smbclient //10.12.23.4/<SHARE NAME> -N` -- connect to client having no password
- `smbclient //10.12.23.4/<SHARE NAME> -U <USERNAME>` -- connect to client 
- `rpcclient -U "" -N 10.12.23.3` -- to connect to null session
- `enum4linux -o 10.12.23.4` -- to give OS info 
- `enum4linux -S 10.12.23.4` -- to give shares info 
- `enum4linux -G 10.12.23.4` -- to give groups info 
- `enum4linux -a 10.12.23.4` -- to give info 
- `enum4linux -r -u "<USERNAME>" -p "<PASSWORD>" 192.212.251.3` -- to give SID

- When connect via rpcclient
	- `enumdomusers` -- give list of users
	- `enumdomgroups` -- give groups
	- `lookupnames <name>` -- give SID
	- `srvinfo` -- to give server info 

- `hydra -l <USERNAME> -P /path/to/password/file 10.12.23.4 <protocol> `  -- to brute force to get login details
- using msfconsole 
	>msfconsole 
	>use auxiliary/scanner/smb/smb_login 
	>set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt 
	>set SMBUser jane 
	>set RHOSTS 192.212.251.3 
	>exploit

- name pipes using msfconsole
	> msfconsole 
	> use auxiliary/scanner/smb/pipe_auditor 
	> set SMBUser admin 
	> set SMBPass password1 
	> set RHOSTS 192.212.251.3 
	> exploit

###### FTP Lesson
- `hydra -l <USERNAME or /path/to/user.txt> -P /path/to/password/file 10.12.23.4 <protocol> -t 4`  -- to brute force to get login details
- `nmap 10.12.23.4 --script ftp-brute --script-args userdb=/path/to/users.txt/file -p 21` -- to brute force to get login details 
- `nmap 10.12.23.4 -p 21 --script ftp-anon`

###### SSH Lesson
- `nmap 10.12.23.4 -p 22 --script ssh2-enum-algos` -- to get algo used for creating key
- `nmap 10.12.23.4 -p 22 --script ssh-hostkey --script-args ssh_hostkey=full` -- to get ssh rsa hostkey
- `nmap 10.12.23.4 -p 22 --script ssh-auth-methods --script-args="ssh.user=<USERNAME>"` -- to check for weak authentication 
- `hydra -l <USERNAME or /path/to/user.txt> -P /path/to/password/file 10.12.23.4 <protocol> `  -- to brute force to get login details
- `nmap 10.12.23.4 --script ssh-brute --script-args userdb=/path/to/users.txt/file -p 22` -- to brute force to get login details 
- using msfconsole
	> msfconsole 
	> use auxiliary/scanner/ssh/ssh_login 
	> set RHOSTS 192.40.231.3 
	> set USERPASS_FILE /usr/share/wordlists/metasploit/root_userpass.txt 
	> set STOP_ON_SUCCESS true 
	> set verbose true 
	> exploit


###### HTTP Lesson
- `whatweb 10.12.23.12` 
- `http 10.12.23.12` -- give http request
- `nmap 10.12.23.12 -sV -p 80 --script http-enum`
- `nmap 10.12.23.12 -sV -p 80 --script http-headers`
- `nmap 10.12.23.12 -sV -p 80 --script banner`

###### SQL Lesson
- `mysql -h 10.12.23.2 -u <USERNAME> --password=<PASSWORD>` -- default login
- `nmap 10.12.23.2 -sV -p 3306 --script mysql-dump-hashes --script-args="username='root',password=''"` -- to dumping MySql hash password
- using msfconsole 
	>msfconsole
	>use auxiliary/scanner/mysql/mysql_hashdump
	>set rhosts
	>set username root
	>set password ""
	>exploit

- `select load_file("/path/to/file")` -- this will give load the file
- `nmap 10.12.23.2 -sV -p 3306 --script=mysql-empty-password`  -- to see if there is any account that can login with empty password
- `nmap 1012.23.2 -sV -p 3306 --script=mysql-info` -- give MySql info
- `nmap 1012.23.2 -sV -p 3306 --script=mysql-users --script-args="mysqluser='<USERNAME>', mysqlpass='<PASSWORD>'"` -- to give info about users
- `nmap 1012.23.2 -sV -p 3306 --script=mysql-databases --script-args="mysqluser='<USERNAME>', mysqlpass='<PASSWORD>'"` -- to give info about databases
- `nmap 10.12.23.2 -sV -p 3306 --script=mysql-variables --script-args="mysqluser='<USERNAME>', mysqlpass='<PASSWORD>'"` -- to give info about variables
- `nmap 10.12.23.2 -sV -p 3306 --script=mysql-audit --script-args "mysql-audit.username='root',mysql-audit.password='',mysql-audit.filename='/usr/share/nmap/n selib/data/mysql-cis.audit'"` -- to give audit info 
- useing msfconsole how many directory are writable
	> use auxiliary/scanner/mysql/mysql_writable_dirs 
	> set DIR_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt 
	> set RHOSTS 192.71.145.3 
	> set VERBOSE false 
	> set username root
	> set PASSWORD "" 
	> exploit

- using msfconsole how many sensitive file are there
	>use auxiliary/scanner/mysql/mysql_file_enum 
	>set RHOSTS 192.71.145.3 
	>set FILE_LIST /usr/share/metasploit-framework/data/wordlists/sensitive_files.txt 
	>set username root
	>set PASSWORD "" 
	>exploit

- `hydra -l root -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.149.194.3 mysql` -- to brute force the login 
- using msfconsole
	> msfconsole 
	> use auxiliary/scanner/mysql/mysql_login 
	> set RHOSTS 192.149.194.3 
	> set USERNAME root 
	> set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 
	> set VERBOSE false 
	> set STOP_ON_SUCCESS true 
	> exploit


- `nmap 10.12.23.4 -p 1433 --script ms-sql-info` --  to get MSSql info
- `nmap 10.12.23.4 -p 1433 --script ms-ntlm-sql-info --script-args mssql.instance.port=1433` --  to get MSSql NTLM info
- using msfconsole to find all possible info
	> use auxiliary/admin/mssql/mssql_enum 
	> set RHOSTS 10.0.20.101 
	> exploit
- `nmap 10.12.23.4 -p 1433 --script ms-sql-brute --script-args userdb=/path/to/file, passdb=/path/to/file` -- to brute force login
- using msfconsole
	> use auxiliary/scanner/mssql/mssql_login 
	> set RHOSTS 10.0.20.101 
	> set USER_FILE /root/Desktop/wordlist/common_users.txt 
	> set PASS_FILE /root/Desktop/wordlist/100-common-passwords.txt
	> set VERBOSE false 
	> exploit

- using msfconsole Extract all MSSQL users
	> use auxiliary/admin/mssql/mssql_enum_sql_logins 
	> set RHOSTS 10.0.20.101 
	> exploit
- `nmap 10.12.23.4 -p 1433 --script ms-sql-empty-password` -- to check if there is empty password
- `nmap 10.12.23.4 -p 1433 --script ms-sql-dump-hashes --script-args mssql.username=<USERNAME>,mssql.password=<PASSWORD>` -- to dump password hash
- `nmap 10.12.23.4 -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=<USERNAME>,mssql.password=<PASSWORD>,ms-sql-cp-cmdshell.cmd="<CMD>"` -- to execute the cmd via mssql
- using msfconsole
	> use auxiliary/admin/mssql/mssql_exec 
	> set RHOSTS 10.0.20.101 
	> set CMD whoami 
	> exploit
- `nmap -p 1433 --script ms-sql-query --script-args mssql.username=<USERNAME>,mssql.password=<PASSWORD>,ms-sql-query.query="SELECT * FROM master..syslogins" 10.0.30.33` -- to execute query to extract sysusers

---
---


