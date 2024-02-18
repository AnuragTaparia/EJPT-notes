###### Tshark
- `tshark -r file.pcap` 
- `tshark -D` -- list of interface
- `tshark -r file.pcap -z io,phs -q` -- to do protocol hierarchy
- `tshark -r file.pcap -Y 'http' ` -- to filter http traffic
- `tshark -r file.pcap -Y 'ip.src==192.168.0.1 && ip.dst==10.101.2.2' ` -- to filter src and dest
- `tshark -r file.pcap -Y 'http.request.method==GET' ` -- to filter http get traffic
- `tshark -r file.pcap -Y 'http.request.method==GET' -Tfields -e frame.time -e ip.src -e http.request.full_uri` -- to filter using timeframe
- `tshark -r file.pcap -Y 'http contains password' ` -- to filter http traffic with password inside the packet
- `tshark -r file.pcap -Y 'http.request.method==GET && http.host==www.example.com' -Tfields -e frame.time -e ip.dst` -- to see get request went for example.com (gives ip of example.com)
- `tshark -r file.pcap -Y 'ip contains example.com && ip.src==10.12.21.2' -Tfields -e ip.dst -e http.cookie` --  to get session ID of example.com
- `tshark -r HTTP_traffic.pcap -Y 'ip.src==192.168.252.128 && http' -Tfields -e http.user_agent` -- give OS details

###### ARP Poisoning
- `echo 1 > /proc/sys/net/ipv4/ip_forward` -- to do ip forwarding
- `arpspoof -i eth1 -t 10.100.13.37 -r 10.100.13.36` 
	- `-t 10.100.13.37`: This option specifies the target IP address that the attacker wants to impersonate or spoof. The ARP packets sent by the attacker will make it appear as if the attacker's machine is the legitimate owner of the IP address "10.100.13.37." 
	- `-r 10.100.13.36`: This option specifies the IP address of the real or legitimate owner of the IP address "10.100.13.37." The attacker is telling the target (in this case, "10.100.13.37") that the MAC address corresponding to "10.100.13.36" should be associated with the IP address "10.100.13.37." This essentially tricks the target into sending its traffic to the attacker instead of the legitimate owner.
- 