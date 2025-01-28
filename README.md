# Using-Wireshark-to-Detect-a-DNS-Tunneling-Attack

---

## Overview

“In cybersecurity, sometimes the answer is hidden in the details, buried deep within network traffic data.”

As a SOC Analyst, I’ve learned that the most revealing insights often lurk in the minutiae of network traffic data. This principle came to fruition during a recent challenge I addressed while freelancing for a company whose name I’ll keep confidential for privacy reasons.


**Tools I Used**
Before diving into the steps, here’s a quick look at the tools I used:

Ubuntu (Linux Distro)
Oracle VM VirtualBox
Wireshark (can be installed on your Linux using the command below)

sudo apt install wireshark


Now, let’s jump into the investigation.


Before narrowing down specific areas, I started my investigation by looking at Wireshark’s Statistics options, which provide an excellent overview of the captured traffic. I could easily get stats for File properties, Resolved Addresses, Protocol Hierarchy, Conversations, Endpoints, Packet Lengths..and a lot more.


![1](https://imgur.com/UAqfO5l.png)

---
Here are the primary statistics I used to begin my analysis:

**1. Capture File Properties**
This gives a quick snapshot of packet counts, capture duration, and timestamps. Always a good first step to get a feel for the scale of the data.


![2](https://imgur.com/hc8vqwe.png)

Front the pop-up above, we can see the following details;

File size (11MB)
The time and date the first and last packet was captured (2023–05–17 16:32:04 -19:06:49 )
Total packets captured — 39,106 packets
Total packets displayed — 39,106 packets


---
2. Protocol Hierarchy
This feature is invaluable for quickly identifying which protocols dominate the traffic. This is key, especially when you’re dealing with abnormal traffic — sometimes, the issue lies in a spike of specific protocol usage.


![3](https://imgur.com/sl1Ctag.png)

From the popup shown above, We can see a structured view of the different network protocols present in the captured traffic, showing how much of the overall traffic is related to each protocol. It helps users quickly understand what types of protocols are in use and their relative prevalence.

It is very obvious that the protocol with the most packets is the UDP protocol, of which the Domain Name System (DNS) has about 29,771 packets which means there were a lot of DNS queries during the attack. Since there is more DNS Traffic, I think it is worth looking at.



---
**3. Conversations**

This statistic breaks down traffic between specific IP addresses, which is helpful for tracking who is talking to whom. A “conversation” in this context refers to a communication session between two endpoints, such as two IP addresses or two MAC addresses.


![4](https://imgur.com/pLi8qf9.png)


This feature helps to analyze the traffic exchanged between pairs of devices or systems, which is particularly useful for network troubleshooting or monitoring.

The Investigation Unfolds
Here’s how I broke down the case to find the culprit and unravel the DNS tunneling attack.

**Total Packets in the Capture File**

The first step is always about assessing the sheer volume of the data you’re working with. To get this, I navigated to Statistics > File properties to view the overall number of packets captured. I didn’t know what I was looking for at this point, so I just wanted to know the size of the dataset.

The file contained 39,106 packets in total, giving me an idea of how much data I needed to sift through.

**The DNS Query**

To get a sense of what domain names were being queried, I applied a display filter for DNS traffic (dns). This helped me zero in on the first domain name queried, which was webmasterdev[.]com.


![5](https://imgur.com/iGixjW0.png)


Following the DNS query, I needed to see which IP address this domain resolved to. By inspecting the DNS response packet, I found that webmasterdev[.]com resolved to 184.168.98.68.


![6](https://imgur.com/2ZaF2yH.png)


So I had to confirm if truly the domain webmasterdev[.]com was resolved to the IP address 184.168.98.68 using the nslookup command as it’s shown below;


![7](https://imgur.com/xybUud6.png)



So far everything looks good and nothing looks suspicious yet as the first dns query seems right.

Since I was expecting some kind of file download or data exchange, I applied a filter for HTTP traffic (http). This returned 8 packets, confirming that HTTP (not secure) communication was indeed taking place.


![8](https://imgur.com/dIENp47.png)



Next, I needed to find out what the victim (172.16.1.16) requested from the server. By following the HTTP stream in Wireshark, I uncovered the relative path the victim accessed: 9GQ5A8/6ctf5JL. At this point, I knew a file was being downloaded, but I didn’t yet know what type of file it was.



![9](https://imgur.com/nCO73Tn.png)


By examining the HTTP response headers, I found that the server reported the content type of the file as image/gif. However, I was skeptical because attackers often disguise malicious files as something else.

To confirm my suspicions, I looked at the file signature — also known as magic bytes. Despite the file being reported as an image or gif (The file signature for jpeg is ÿØÿÛ and for gif the file signature is supposed to be GIF87a, GIF89a), the magic bytes revealed the actual file type was an executable ( MZ ). This was a critical turning point in the investigation because it indicated the presence of a potential malware download.

Digging deeper into the HTTP request headers, I found that the victim used Windows PowerShell to download the file. This suggested that the attacker might have used a script to automate the malicious download, making the attack even more insidious.

**Getting the file Hash**

To further validate my findings, I extracted the file from wireshark, saved it in a folder and got the hash using the command below;


![10](https://imgur.com/LhA3kCf.png)


I submitted it to VirusTotal, an online service that scans files for malware. VirusTotal identified the file as a variant of the PIKABOT TROJAN (Learn More About Pikabot Trojan here), 59 out of 75 Vendors reported the file as being malicious, which confirmed that the endpoint was indeed infected with malware.


![11](https://imgur.com/QBY7EwR.png)



By this point, I knew the attack could involve DNS, so I went back to check which protocol dominated the UDP packets. It turned out to be DNS protocol, further confirming my suspicion that DNS was being abused in this attack.


Finally, I analyzed the DNS traffic more closely and found that a domain, steasteel[.]net was repeatedly queried throughout the capture.


![12](https://imgur.com/qeO265o.png)


I looked up the domain steasteel[.]net on Virus-total and it came back malicious, 7 out of 94 vendors flagged the domain as malicious.


![13](https://imgur.com/skijmsP.png)


This repetition is often indicative of DNS tunneling, where attackers use DNS queries to communicate or exfiltrate data from the network.

Conclusion
The attack turned out to be DNS tunneling, a covert channel that uses DNS queries to tunnel malicious traffic.

In simple terms, here’s what the attacker did:

**Gained access to the victim’s computer:** The attacker found a way into a computer (most likely through something like a phishing email or exploiting a weak point in the system).


**Used DNS to communicate:** Instead of using common methods like web traffic, the attacker used something called DNS (which is usually used to match website names to their IP addresses) to send secret messages back and forth to a server they controlled. This allowed them to hide their communication because DNS traffic usually doesn’t raise suspicion.


**Downloaded a disguised malicious file:** The attacker used PowerShell (a built-in Windows tool) to download a file. The file was disguised as an image (image/gif), but in reality, it was a malicious program designed to infect the computer.


**Installed a Trojan virus:** The downloaded file was a Pikabot Trojan. Once installed, this virus gave the attacker more control over the computer and allowed them to steal information or cause more damage later.


**Kept communication hidden in DNS queries:** The attacker continued to send and receive commands by repeatedly using DNS queries to a domain called steasteel[.]net. This method of communication was hidden inside normal-looking DNS traffic, which made it harder for the system to detect.


In summary, the attacker cleverly used normal DNS communication to secretly control the victim’s machine and install a virus, while trying to stay under the radar.



















