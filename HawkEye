CyberDefenders:

You can download the challenge file from the link below.
Link: https://cyberdefenders.org/blueteam-ctf-challenges/91


Scenario:
An accountant at your organization received an email regarding an invoice with a download link. 
Suspicious network traffic was observed shortly after opening the email. 
As a SOC analyst, investigate the network trace and analyze exfiltration attempts.

Tools:
Wireshark
BrimSecurity
Apackets

As per above information form the challenge, The tools that can help us to answer the challenges would be Wireshark, BrimSecurity and Apackets.

But we are not limited to use other approach to get what is needed from the questions.

What tools i used?
capinfos
tshark
wireshark
whois

virustotal page.


We will try to do a different approach and we will be using the tshark command as long as it permits it since the challenge data is a pcap file 
and I am trying to learn the tshark command line arguments :)
A littel bit of capinfos

Lets go.

Questions

#1
How many packets does the capture have?
*** using capinfos, you can see the number of packets for this pcap file
command: capinfos stealer.pcap
answer: 4003


#2
At what time was the first packet captured?
*** using capinfos, you can see the timing of the packets ( First / Last )
you need to convert it to UTC ( from your current localtime; mine is GMT+8 )
answer: 2019-04-10 20:37:07 UTC


#3
What is the duration of the capture?
*** using capinfos, you can see the timing of the packets ( First / Last )
subtract the last packet time to first packet time
answer: 01:03:41


For the first 3 questions, we can use the capinfos to get the pcap file information.

└─$ capinfos stealer.pcap                      
File name:           stealer.pcap
File type:           Wireshark/tcpdump/... - pcap
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: 65535 bytes
Number of packets:   4,003
File size:           2,454kB
Data size:           2,390kB
Capture duration:    3821.561233 seconds
First packet time:   2019-04-11 04:37:07.129730
Last packet time:    2019-04-11 05:40:48.690963
Data byte rate:      625 bytes/s
Data bit rate:       5,003 bits/s
Average packet size: 597.08 bytes
Average packet rate: 1 packets/s
SHA256:              22106927c11836d29078dfbec20be9d6b61b1f3f47f95c758acc47a1fb424e51
RIPEMD160:           84cba6f095e6ba0243c27e4770e708c69443f49b
SHA1:                084d3ade8ce828e0233b69275c8554a86d9670ab
Strict time order:   True
Number of interfaces in file: 1
Interface #0 info:
                     Encapsulation = Ethernet (1 - ether)
                     Capture length = 65535
                     Time precision = microseconds (6)
                     Time ticks per second = 1000000
                     Number of stat entries = 0
                     Number of packets = 4003



#4
What is the most active computer at the link level?
*** you can use tshark -r stealer.pcap -n -q -z conv,eth
or from wireshark, go to Stats->Conversation .. Eth tab and sort the packets

└─$ tshark -r stealer.pcap -n -q -z conv,eth 
================================================================================
Ethernet Conversations
Filter:<No Filter>
                                               |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
00:08:02:1c:47:ae    <-> 20:e5:2a:b6:93:f1       1776 2,132kB      1576 109kB        3352 2,241kB      47.459211000      3730.4030
00:08:02:1c:47:ae    <-> a4:1f:72:c2:09:6a        234 45kB          279 68kB          513 113kB         0.000000000      3821.5612
00:08:02:1c:47:ae    <-> 01:00:5e:7f:ff:fa          0 0bytes         74 28kB           74 28kB        109.882622000      3666.1008
00:08:02:1c:47:ae    <-> ff:ff:ff:ff:ff:ff          0 0bytes         31 3,534bytes      31 3,534bytes    46.633556000      2823.2623
00:08:02:1c:47:ae    <-> 01:00:5e:00:00:16          0 0bytes         23 1,258bytes      23 1,258bytes   109.878104000      3651.2201
00:08:02:1c:47:ae    <-> 01:00:5e:00:00:fc          0 0bytes         10 750bytes       10 750bytes   2663.801528000      1096.9531
================================================================================


answer: 00:08:02:1c:47:ae


#5
Manufacturer of the NIC of the most active system at the link level?
*** you can go to macaddress.io and input the mac address 00:08:02:1c:47:ae

answer: Hewlett-Packard




#6
Where is the headquarter of the company that manufactured the NIC of the most active computer at the link level?
*** check the Headquarters of Hewlett Packard - Wikipedia
https://en.wikipedia.org/wiki/Hewlett-Packard

answer: Palo Alto


#7
The organization works with private addressing and netmask /24. How many computers in the organization are involved in the capture?
*** tshark -r stealer.pcap -q -z conv,ip - count the internal ip

└─$ tshark -r stealer.pcap -q -z conv,ip
================================================================================
IPv4 Conversations
Filter:<No Filter>
                                               |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
10.4.10.132          <-> 217.182.138.150         1576 2,110kB      1371 74kB         2947 2,185kB      47.459211000         1.5496
10.4.10.4            <-> 10.4.10.132              279 68kB          234 45kB          513 113kB         0.000000000      3821.5612
10.4.10.132          <-> 23.229.162.69            161 13kB          119 25kB          280 38kB         68.784554000      3709.0776
10.4.10.132          <-> 239.255.255.250            0 0bytes         74 28kB           74 28kB        109.882622000      3666.1008
10.4.10.132          <-> 66.171.248.178            28 2,716bytes      35 2,499bytes      63 5,215bytes    68.581965000      3626.9943
10.4.10.2            <-> 10.4.10.132               42 4,620bytes       0 0bytes         42 4,620bytes  2667.119568000      1040.4795
10.4.10.132          <-> 10.4.10.255                0 0bytes         30 3,192bytes      30 3,192bytes    46.633556000      2823.2623
10.4.10.132          <-> 224.0.0.22                 0 0bytes         23 1,258bytes      23 1,258bytes   109.878104000      3651.2201
10.4.10.132          <-> 216.58.193.131            11 5,716bytes       9 2,511bytes      20 8,227bytes   651.547727000         0.3497
10.4.10.132          <-> 224.0.0.252                0 0bytes         10 750bytes       10 750bytes   2663.801528000      1096.9531
10.4.10.132          <-> 255.255.255.255            0 0bytes          1 342bytes        1 342bytes    649.194871000         0.0000
================================================================================

internal ip : 10.4.10.2, 10.4.10.4, 10.4.10.132

answer: 3


#8
What is the name of the most active computer at the network level?
*** from the previous question we know that the top talker is 10.4.10.132
We can check the hostname of that
- tshark -r stealer.pcap -Y 'ip.addr == 10.4.10.132' -Y 'nbns'

answer: BEIJING-5CD1-PC


#9
What is the IP of the organization's DNS server?
*** type dns in the wireshark query. then look for the dns response
- tshark -r stealer.pcap -Y 'ip.addr == 10.4.10.132' -Y 'dns' | grep "Standard query response"| awk '{print $3}'| sort -rn |uniq

└─$ tshark -r stealer.pcap -Y 'ip.addr == 10.4.10.132' -Y 'dns' | grep "Standard query response"| awk '{print $3}'| sort -rn |uniq
10.4.10.4

dissect the above command. I used the top talker ip address then add dns packets ( -Y 'dns' ) , look for the string "Standard query response",
get and print the third field ( awk '{print $3}' ), sort it ( sort -rn ) , then just output the unique result.

answer: 10.4.10.4


#10
What domain is the victim asking about in packet 204?
*** from wireshark, click Go  -> goto packet then enter 204
look at the queries, and you will see the answer

note: you can use this tshark query as well.
tshark -r stealer.pcap |grep ^"  204"


└─$ tshark -r stealer.pcap |grep ^"  204"
  204  46.661287  10.4.10.132 → 10.4.10.4    DNS 81     Standard query 0xa002 A proforma-invoices.com

answer: proforma-invoices.com



#11
What is the IP of the domain in the previous question?
*** tshark -r stealer.pcap -Y 'dns' |grep proforma-invoices.com

└─$ tshark -r stealer.pcap -Y 'dns' |grep proforma-invoices.com
  204  46.661287  10.4.10.132 → 10.4.10.4    DNS 81     Standard query 0xa002 A proforma-invoices.com
  206  47.447289    10.4.10.4 → 10.4.10.132  DNS 97     Standard query response 0xa002 A proforma-invoices.com A 217.182.138.150


answer: 217.182.138.150


#12
Indicate the country to which the IP in the previous section belongs.
you can use the whois command from your linux machine ( be sure that you can reach the internet )

*** whois 217.182.138.150|grep -i country

└─$ whois 217.182.138.150|grep -i country
country:        FR
country:        FR


answer: France


#13
What operating system does the victim's computer run?
*** tshark  -Y 'ip.addr == 10.4.10.132' -T fields -e http.user_agent -r stealer.pcap| uniq
*** wireshark - (http.user_agent) && (ip.addr == 10.4.10.132) 

└─$ tshark  -Y 'ip.addr == 10.4.10.132' -T fields -e http.user_agent -r stealer.pcap| uniq

Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)



answer: Windows NT 6.1


#14
What is the name of the malicious file downloaded by the accountant?
*** tshark  -Y 'ip.addr == 10.4.10.132 && http.request.method == "GET"' -T fields -e http.host -e http.request.uri  -r stealer.pcap| uniq
*** wireshark - (((ip.addr == 10.4.10.132)) && (http.request.method == "GET")) && (http.request.full_uri )

└─$ tshark  -Y 'ip.addr == 10.4.10.132 && http.request.method == "GET"' -T fields -e http.host -e http.request.uri  -r stealer.pcap| uniq
proforma-invoices.com   /proforma/tkraw_Protected99.exe
bot.whatismyipaddress.com       /
                                                                                                                                                   

answer:  tkraw_Protected99.exe




#15
What is the md5 hash of the downloaded file?
*** tshark -r stealer.pcap --export-objects http,extracted - this will extract objects from http stream and write it to "extracted" folder
*** wireshark - go to File -> Export objects -> http then select the file you want to export
- once exported, run the md5sum on the file


answer: 71826ba081e303866ce2a2534491a2f7


#16
What is the name of the malware according to Malwarebytes?
*** go to virustotal and upload the exe file and check the info line with Malwarebytes
answer: Spyware.HawkEyeKeyLogger


#17
What software runs the webserver that hosts the malware?
*** wireshark - (ip.addr == 217.182.138.150) && (http.server) 
*** tshark - tshark  -r stealer.pcap -Y 'ip.addr == 217.182.138.150' -T fields -e http.server  | sort -nr| uniq

└─$ tshark  -r stealer.pcap -Y 'ip.addr == 217.182.138.150' -T fields -e http.server  | sort -nr| uniq 
LiteSpeed


answer: Litespeed


#18
What is the public IP of the victim's computer?
*** wireshark - ip.addr == 10.4.10.132 && data-text-lines

answer: 173.66.146.112

#19
In which country is the email server to which the stolen information is sent?
*** whois secureserver.net | grep -i country

answer: United States


#20
What is the domain's creation date to which the information is exfiltrated?
*** whois the domain of the email to: macwinlogistics.in
*** tshark - tshark  -Y 'ip.addr == 10.4.10.132 && smtp' -r stealer.pcap | grep RCPT | awk '{print $10}'| cut -d: -f2 | cut -d\@ -f2| cut -d\> -f1| uniq| xargs whois |grep Creation


└─$ tshark  -Y 'ip.addr == 10.4.10.132 && smtp' -r stealer.pcap | grep RCPT | awk '{print $10}'| cut -d: -f2 | cut -d\@ -f2| cut -d\> -f1| uniq| xargs whois |grep "Creation Date"
Creation Date: 2014-02-08T10:31:26Z

let's breakdown the commands.
tshark  -Y 'ip.addr == 10.4.10.132 && smtp' -r stealer.pcap   <- standard tshark query looking for the ip address 10.4.10.132 and smtp
grep RCPT   <- searching for string "RCPT"
awk '{print $10}'   <- printing the 10th field of the previous result
cut -d: -f2   <- printing the 2nd field using a ":" the delimeter from the previous result
cut -d\@ -f2  <- printing the 2nd field using a "@" the delimeter from the previous result
cut -d\> -f1  <- printing the 1st field using ">" as the delimter from the previous result
uniq <- getting only the unique from the previous result
xargs whois | grep Creation   <- using the whois against the result from the previous output and searching for the string "Creation Date"


answer: 2014-02-08 


#21
Analyzing the first extraction of information. What software runs the email server to which the stolen data is sent?
*** wireshark - 
*** tshark  -Y 'ip.addr == 10.4.10.132 && smtp' -r stealer.pcap -Y 'smtp.response.code == 220'


└─$ tshark  -Y 'ip.addr == 10.4.10.132 && smtp' -r stealer.pcap -Y 'smtp.response.code == 220'
 3175  69.160215 23.229.162.69 → 10.4.10.132  SMTP 251   p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91 #1 Wed, 10 Apr 2019 13:38:15 -0700 ,We do not authorize the use of this system to transport unsolicited, ,and/or bulk e-mail.  S: 220-p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91 #1 Wed, 10 Apr 2019 13:38:15 -0700  | We do not authorize the use of this system to transport unsolicited,  | and/or bulk e-mail.
 3306 673.516672 23.229.162.69 → 10.4.10.132  SMTP 251   p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91 #1 Wed, 10 Apr 2019 13:48:20 -0700 ,We do not authorize the use of this system to transport unsolicited, ,and/or bulk e-mail.  S: 220-p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91 #1 Wed, 10 Apr 2019 13:48:20 -0700  | We do not authorize the use of this system to transport unsolicited,  | and/or bulk e-mail.
 3393 1277.625627 23.229.162.69 → 10.4.10.132  SMTP 251   p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91 #1 Wed, 10 Apr 2019 13:58:24 -0700 ,We do not authorize the use of this system to transport unsolicited, ,and/or bulk e-mail.  S: 220-p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91 #1 Wed, 10 Apr 2019 13:58:24 -0700  | We do not authorize the use of this system to transport unsolicited,  | and/or bulk e-mail.
 3478 1883.380509 23.229.162.69 → 10.4.10.132  SMTP 251   p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91 #1 Wed, 10 Apr 2019 14:08:30 -0700 ,We do not authorize the use of this system to transport unsolicited, ,and/or bulk e-mail.  S: 220-p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91 #1 Wed, 10 Apr 2019 14:08:30 -0700  | We do not authorize the use of this system to transport unsolicited,  | and/or bulk e-mail.
 3593 2487.518233 23.229.162.69 → 10.4.10.132  SMTP 251   p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91 #1 Wed, 10 Apr 2019 14:18:34 -0700 ,We do not authorize the use of this system to transport unsolicited, ,and/or bulk e-mail.  S: 220-p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91 #1 Wed, 10 Apr 2019 14:18:34 -0700  | We do not authorize the use of this system to transport unsolicited,  | and/or bulk e-mail.
 3848 3091.686742 23.229.162.69 → 10.4.10.132  SMTP 251   p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91 #1 Wed, 10 Apr 2019 14:28:38 -0700 ,We do not authorize the use of this system to transport unsolicited, ,and/or bulk e-mail.  S: 220-p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91 #1 Wed, 10 Apr 2019 14:28:38 -0700  | We do not authorize the use of this system to transport unsolicited,  | and/or bulk e-mail.
 3926 3695.800024 23.229.162.69 → 10.4.10.132  SMTP 251   p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91 #1 Wed, 10 Apr 2019 14:38:42 -0700 ,We do not authorize the use of this system to transport unsolicited, ,and/or bulk e-mail.  S: 220-p3plcpnl0413.prod.phx3.secureserver.net ESMTP Exim 4.91 #1 Wed, 10 Apr 2019 14:38:42 -0700  | We do not authorize the use of this system to transport unsolicited,  | and/or bulk e-mail.


answer: Exim 4.91



#22
To which email account is the stolen information sent?

*** tshark  -Y 'ip.addr == 10.4.10.132 && smtp' -r stealer.pcap |grep "RCPT TO:"

└─$ tshark  -Y 'ip.addr == 10.4.10.132 && smtp' -r stealer.pcap |grep "RCPT TO:"
 3188  69.432035  10.4.10.132 → 23.229.162.69 SMTP 94     C: RCPT TO:<sales.del@macwinlogistics.in>
 3319 673.785075  10.4.10.132 → 23.229.162.69 SMTP 94     C: RCPT TO:<sales.del@macwinlogistics.in>
 3406 1277.899726  10.4.10.132 → 23.229.162.69 SMTP 94     C: RCPT TO:<sales.del@macwinlogistics.in>
 3491 1883.644360  10.4.10.132 → 23.229.162.69 SMTP 94     C: RCPT TO:<sales.del@macwinlogistics.in>
 3606 2487.785900  10.4.10.132 → 23.229.162.69 SMTP 94     C: RCPT TO:<sales.del@macwinlogistics.in>
 3861 3091.961946  10.4.10.132 → 23.229.162.69 SMTP 94     C: RCPT TO:<sales.del@macwinlogistics.in>
 3939 3696.075266  10.4.10.132 → 23.229.162.69 SMTP 94     C: RCPT TO:<sales.del@macwinlogistics.in>

answer: sales.del@macwinlogistics.in


#23
What is the password used by the malware to send the email?

*** tshark  -Y 'ip.addr == 10.4.10.132 && smtp' -r stealer.pcap |grep -i -C2 "sales.del@macwinlogistics.in" |grep -i -C2 pass | tail


└─$ tshark  -Y 'ip.addr == 10.4.10.132 && smtp' -r stealer.pcap |grep -i -C2 "sales.del@macwinlogistics.in" |grep -i -C2 pass | tail
 3855 3091.820830  10.4.10.132 → 23.229.162.69 SMTP 68     C: Pass: Sales@23
 3857 3091.892674 23.229.162.69 → 10.4.10.132  SMTP 84   Authentication succeeded  S: 235 Authentication succeeded
 3858 3091.892837  10.4.10.132 → 23.229.162.69 SMTP 96     C: MAIL FROM:<sales.del@macwinlogistics.in>
--
 3929 3695.865990 23.229.162.69 → 10.4.10.132  SMTP 261   p3plcpnl0413.prod.phx3.secureserver.net Hello Beijing-5cd1-PC [173.66.146.112],SIZE 52428800,8BITMIME,PIPELINING,AUTH PLAIN LOGIN,CHUNKING,STARTTLS,SMTPUTF8,HELP  S: 250-p3plcpnl0413.prod.phx3.secureserver.net Hello Beijing-5cd1-PC [173.66.146.112] | SIZE 52428800 | 8BITMIME | PIPELINING | AUTH PLAIN LOGIN | CHUNKING | STARTTLS | SMTPUTF8 | HELP
 3930 3695.866240  10.4.10.132 → 23.229.162.69 SMTP 107     C: AUTH login User: sales.del@macwinlogistics.in
 3932 3695.935718 23.229.162.69 → 10.4.10.132  SMTP 72   Password:  S: 334 Password:
 3933 3695.935927  10.4.10.132 → 23.229.162.69 SMTP 68     C: Pass: Sales@23
 3935 3696.000969 23.229.162.69 → 10.4.10.132  SMTP 84   Authentication succeeded  S: 235 Authentication succeeded
 3936 3696.001168  10.4.10.132 → 23.229.162.69 SMTP 96     C: MAIL FROM:<sales.del@macwinlogistics.in>
                                                                                                                      
answer: Sales@23


#24
Which malware variant exfiltrated the data?
# try googling around.

answer: Reborn v9


#25
What are the bankofamerica access credentials? (username:password)
using wireshark , search for tcp.stream eq 37

answer: roman.mcguire:P@ssw0rd$


#26
Every how many minutes does the collected data get exfiltrated?
using wireshark, search using (ip.src == 10.4.10.132) && (ip.dst == 23.229.162.69) - 

answer: 10
