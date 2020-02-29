# scanGo

**scanGo** is pyhton based CLI tool that checks for vulnerabilities using OSINT tools. This tool attracts any web application or domain belonging to a corporate or an individual to ensure security and robustness of their system. The aim of the software  product is to detect levels of vulnerabilities, such as high, medium and informative present in one web application.

The proposed system is based on proprietary python architecture which can independently work using the required python modules. Hence, no such external interface is required in order to execute the system. But, in order to gather all possible subdomains from a given domain, an open source python based tool, sublist3r, can be used and encapsulated with the scanner file. This will provide with more number of subdomains in comparatively less time.


![alt text](https://github.com/gunishachhabra/scanGo/blob/scanGo_sc/1.png)

# To install
```git clone https://github.com/gunishachhabra/scanGo.git```
> This version of scanGo supports **python 3**

# Current Features 

### openPortsDetectionTool 
This module detects for the informative level of vulnerability where in possible open ports are detected and displayed. It not only presents the open ports but also the services offered by them.

### ServerInfoTool 
The ServerInfoTool is the module to detect the server information which is said to be a sensitive data. Many web applications and APIs do not properly protect sensitive data, such as financial, server Information, healthcare, and PII. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes. Sensitive data may be compromised without extra protection, such as encryption at rest or in transit, and requires special precautions when exchanged with the browser.

### sqlInjectionTool 
The said module checks for presence of SQL Injection Vulnerability. Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter as part of a command or query. The attacker’s hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.

### subdomainTakeverTool 
A module to check for subdomain takeover. The basic premise of a subdomain takeover is a host that points to a particular service not currently in use, which an adversary can use to serve content on the vulnerable subdomain by setting up an account on the third-party service.
![alt text](https://github.com/gunishachhabra/scanGo/blob/scanGo_sc/2.png)

### SecurityHeadersCheck_Tool 
This is the module for informative level vulnerability to check for X-XSS Protection Value which when not properly enabled leads to Security misconfiguration. Security misconfiguration is the most commonly seen issue. This is commonly a result of insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information. Not only must all operating systems, frameworks, libraries, and applications be securely configured, but they must be patched/upgraded in a timely fashion. It also checks for x-frame-options, Content Security Policy (CSP), HTTP Strict Transport Security (HSTS) Headers.

### DNS_zone_transfer_check
A misconfigured DNS Zone Transfer will lead to leaks of user names and relevant IP addresses. And it can also lead to a leak of confidential data online. The tool attempts to check for potential zone transfer by automatically running the commands to perform the attack. This vulnerability will lead to leakage of hostnames and the associated IP Addresses, which could lead to a further target of the organization and also sometimes it may lead to leakage of confidential data of the firm, who developed and maintaining this server.

### HTTPHeaderInjection
HTTP Header Injection vulnerabilities occur when user input is insecurely included within server responses headers. Specifically they are based around the idea that an attacker can cause the server to generate a response which includes carriage-return and line-feed characters (or %0D and %0A respectively in their URI encoded forms) within the server response header the attacker may be able to add crafted headers themselves. Header Injection can allow for attacks such as response splitting, session fixation, cross-site scripting, and malicious redirection. The tool, hence performs the basic check of header Injection by embedding a custom header data inside the legitimate headers and waits for the response. If the response header reverts with the hoax data, then the presence of the vulnerability is assured.

### missingSPF
An SPF record is a Sender Policy Framework record. It's used to indicate to mail exchanges which hosts are authorized to send mail for a domain. An SPF record is a type of Domain Name Service (DNS) record that identifies which mail servers are permitted to send email on behalf of your domain. The purpose of an SPF record is to prevent spammers from sending messages with forged From addresses at legitimate domain. This tool performs check for the presence of SPF record and also detect its mechanism configuration as best, good, average, low as compared with the given types of rejection level :
- : -all (reject or fail them - don't deliver the email if anything does not match) 
- ~all (soft-fail them - accept them, but mark it as 'suspicious')
- +all (pass regardless of match - accept anything from the domain)
- ?all (neutral - accept it, nothing can be said about the validity if there isn't an IP match)

### infoDisclosureHTTP
This tool checks for the internal information disclosure in HTTP Headers. HTTP headers are sent when a browser to web server communication takes place. The HTTP headers are mainly used to provide information to help handle the request or response, but some of the data tend to disclose information that might help an attacker to get the idea or overview of the system, or discover a door to exploit the system. Hence this tool check for server or location data inside the HTTP header of the requested website and servers as an informative vulnerability detection.

### XSRF_check
Cross-site request forgery, also known as one-click attack or session riding and abbreviated as CSRF or XSRF, is a type of exploit of a website where a user is tricked into submitting data that he/she never intended to do.  Cross-site request forgery can’t be detected easily by an automatic tool, as this depends on the attacker’s interest to sabotage a victim. Hence this tool performs basic checks that prevent a webpage against CSRF attack. This is done by checking CSRF tokens for a webpage and looking at the cookie attributes, SameSite and HTTPOnly, that help mitigate this attack.

# Usage
> Inside the scanGo directory enter the below command : 
```python3 scannerInterface.py ```

# Credits
[Sublit3r](https://github.com/aboul3la/Sublist3r) - The python tool designed to enumerate subdomains of websites.

