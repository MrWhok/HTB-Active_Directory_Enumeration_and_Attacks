# HTB-Active_Directory_Enumeration_and_Attacks

## Table of Contents
1. [Initial Enumeration](#initial-enumeration)
    1. [External Recon and Enumeration Principles](#external-recon-and-enumeration-principles)
    2. [Initial Enumeration of the Domain](#initial-enumeration-of-the-domain)

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

