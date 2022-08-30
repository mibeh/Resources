# Windows Security Info

## Common Backdoor/Persistance Locations & Techniques
- Registry 
- Scheduled Tasks 
- Password Filter 
- Users
- DLL Hijacking (Use process hacker / Procmon)
- Windows Startup
- Services
- Sticky Keys/Accessibility (utilman)
    - including debug keys
- Web Shells 
- Hidden Files and EXEs 

### Registry Based 
- Common Locations
```
\[HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\]
\[HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\]
\[HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices\]
\[HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce\]
\[HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\]

\[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\]
\[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\]
\[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices\]
\[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce\]
\[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\]
```

## Windows Startup 
``` 
**\# Windows NT 6.0 - 10.0 / All Users**
%SystemDrive%\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup

**\# Windows NT 6.0 - 10.0 / Current User**
%SystemDrive%\\Users\\%UserName%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup

**\# Windows NT 5.0 - 5.2**
%SystemDrive%\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup

**\# Windows NT 3.5 - 4.0**
%SystemDrive%\\WINNT\\Profiles\\All Users\\Start Menu\\Programs\\Startup
```



## Password Filter
Windows API PasswordChangeNotify is a function of the Password Filter DLL, more advanced backdoors/malware will utilize the creation of a password filter dll, which is loaded into lsass as a notification package. Can be used to steal passwords as soon as they are changed. 


- Located at `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`
    - Under Notification Packages
    - This should be blank unless password policy is set  then
        - sceli & rassfm will be a notification package.
    - The malicous dll will need to be located in system32
- To audit for this use process explorer for the lsass process & inspect loaded dlls
    - You will notice immediately if something is wrong. 
 
- Command to query key 
    - ```REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Notification Packages"```

## Disable Net Session Enumeration 
(Recon defense - Bloodhound uses this as a method of mapping out credentials/sessions throughout the network) (Also prevents Null Session Domain controller Enumeration)
- Domain Controllers (Windows 2003, 2008, 2008 R2, 2012/R2+)
    - `Computer configuration\\Policies\\Windows settings\\Security Settings\\Local Policies\\SecurityOptions`
        - Enable:  
                - Network access: Restrict Anonymous access to Named Pipes and Shares  
                - Network access: Do not allow anonymous enumeration of SAM accounts  
                - Network access: Do not allow anonymous enumeration of SAM accounts and shares  
                - Network access: Shares that can be accessed anonymously  
        - Disable:  
                - Network access: Let Everyone permissions apply to anonymous users  
                - Network access: Allow anonymous SID/Name translation
- Registry (Update These values) 
    - `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA`
    - RestrictAnonymous = 1  
    - Restrict AnonymousSAM = 1  
    - EveryoneIncludesAnonymous = 0
- Other
    - `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameter` 
    - NullSessionPipes: (blank it out)
    - RestrictNullSessAccess = 1



Refs: 
- https://inner-tech.blogspot.com/2015/09/null-session-domain-controller.html 
- http://jbcomp.com/disable-smb-null-windows-2012/

## Disable WPAD 

- gpedit.msc -> User Configuration -> Policies -> Windows Settings -> connection/automatic browser configuration -> automatically detect configuration settings (disable) 

## Disable LLMNR & NetBIOS/NBT-NS
( Allows for passive credential harvesting if they get on the internal network through tools like responder)
- gpedit.msc 
    - Local Computer Policy -> Computer Configuration -> Administrative Templates -> Network -> DNS Client
        - Turn Off Multicast Name Resolution” and set it to “Enabled”
- Also disable network discovery
- Disablign NBT-NS
    - regedit.exe
        -`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\`
        - set `NetbiosOptions` => 2  
- Disable `Computer Browser` Service in services 

Refs: 
- https://github.com/Spiderlabs/Responder
- https://www.surecloud.com/sc-news/local-network-vulnerabilities-llmnr-nbt-ns-poisoning

## Disable Windows Script Host (WSH)/Control Scripting File Extensions (All Windows Versions. Great for NT/2000/Windows XP) 

Removes the ability to run vbs scripts/wscript/csript scripts, even by an administrator -- **Extremely** useful

Run the following reg command (Need administrator command prompt). 

`reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d 0 /f`

- Manually: 
    - HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings
        - Created new DWORD
            - Value: `Enabled`
                - Set Value => 0 

To undo the changes run:
`reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d 1 /f`


Afer running that command, trying to run .vbs, wscript, csript scripts etc.. will display the error: "Windows Script Host Access is disabled on this machine Contact you administrator for details"



references: 
- https://technet.microsoft.com/en-us/library/ee198684.aspx

## Disable local Administrator Accounts from performing network logons
(Pass-the-Hash Mitigation)
- Set `HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\FilterAdministratorToken ==> "1"` 

- Manually (Requires Group Policy)
    - Under "User Rights Assignment"
        - "Deny access to this computer from the network"
            - Add "local account" as value 
            - gpupdate /force 
    - Test by trying to access network system via network style activity 
        - ex: `dir \\somecomputer\c$` (This should fail )

## Disable WDigest 

Disabling WDigest prevents clear-text passwords from being dumped from memory when cached. (Hashes will still dump)
- Need KB2871997
- regedit.exe -> Create/Set 
    -  `HKEY_LOCAL_MACHINE\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest`
        - "UseLogonCredential" => 0

## Disable SMBv1 

- Powershell
    - `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 –Force` 

## Applocker / Application White Listing
- Follow the DoD's/NSA Applocker Guide 


### Binaries you probably don't need to use that they will probably use 
- mshta.exe - Can be used to execute hta scripts remotly (also an application whitelisting bypass technique)
    - Location - `C:\windows\system32\mshta.exe`
- regsvr32.exe - can be used for legit for applications, but it's used heavily by attackers
    - Use EMET and enable ASR for regsvr32.exe 
    - Maybe use SRP on this binary as well 
- Regsvcs.exe
    - Location - `C:\windows\system32\`
- Regasm.exe
- rundll32.exe
    - Can't really enable SRP for this, too many apps use it. 
    - Use EMET and enable ASR for this
    - Prevent this from connecting to the internet with firewall rules
- bitsadmin.exe / bits.exe (can be used to transfer files)
- MSbuild.exe - can be used to execute powershell , even if it's blocked or not even installed
- On-Screen Keyboard: `C:\Windows\System32\osk.exe`
- Magnifier: `C:\Windows\System32\Magnify.exe`
- Narrator: `C:\Windows\System32\Narrator.exe`
- Display Switcher: `C:\Windows\System32\DisplaySwitch.exe`
- App Switcher: `C:\Windows\System32\AtBroker.exe`

## Put LSA into Protected Mode (Credential Guard) (Windows 8.1/2012 R2+) 
(Prevents Hooking into LSA & easily dumping of credentials, mimikatz etc...)
(Attacker would need to load the mimikatz driver module (much more work))

- Manually
    - regedit.exe
    - HKEY_LOCAL_MACHINE -> System -> CurrentControlSet -> Control -> LSA
        - Create new DWORD (32 bit) 
            - Value: "RunasPPL"
                - Set data value => 1
                 
Requires restart to apply.
- Check the System log in the central pane for a Wininit event that shows  LSASS.exe was started as a protected process with level: 4_.

References: 
- http://blog.jpcert.or.jp/2016/10/verification-of-ad9d.html 



## Disallow Loading of Remote DLLS

This is enabled by default in Windows Server 2012+, & you can deploy as a patch to XP+ and server 2003+

Tools like PowerSploit/Empire have modules that test for this. 

- Manually Enabling (GPO)
    - Computer Configuration -> Administrative Templates -> MSS (Legacy): MSS (SafeDLLSearchMode) -> Enable Safe DDL search mode.

- Registry key is located at:
    - `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session`

## Restricting Access Token / Steal Token

- Via Group Policy
    - Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment: Create a token object 
    - (Should be local system only)
    - Computer Configuration  -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assesment: Replace a process level token 
        - Set to Local Service & Network Service (ONLY)

## Prevent PSEXEC from working 
This can be dangerous if you lose RDP Access to a Machine. 

Run this command: 

```FOR /F "usebackq tokens=2 delims=:" %a IN (`sc.exe sdshow scmanager`) DO  sc.exe sdset scmanager D:(D;;GA;;;NU)%a` ``` 

This should prevent users "on the network" from executing psexc or sc remotely.

Also run:

```reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\psexec.exe"  /v Debugger /t REG_SZ /d svchost.exe```

This adds a debug execution value for the psexec.exe binary, which will launch svchost.exe instead (will prevent psexec from executing anything)

https://hackingandcoffee.com/an-exercise-in-privilege-escalation-and-persistence/

### Defending agaisnt Powershell Attacks

Main steps to take:
1) Deploy Powershell v5 
2) Enable, and Collect Powershell Logs (Script block Logging)
3) SRP/Applocker whenever possible

#### Constrained Language mode
- set the _PSLockdownPolicy
    - `[Enviroment]::SetEnviromentVariable('__PSLockdownPolicy','4','Machine')`
    - Open new PS session, check.
        - `$ExecutionContext.SessionState.LanguageMode`
    
### AppLocker Script Rule
- Create applocker policy to allow scripts from a directory 
`Set-ApplockerPolicy (New-AppLockerPolicy -RuleType Path -FileInformation "C:\\Path\\where\\scripts\\are\\okay\\")`

- Check to see if policy Applied
Get-ApplockerPolicy -Local

- Then create Script Policy Denying all Powershell/PS1

### Log Powershell Activity
1) In Group Policy
    - `Computer Configuration\Policies\Administrative Template\Windows Components\Windows PowerShell` 
    - Turn on Module Logging
    - Value: => ``"*"``

2) Also Enable Script Block Logging (Powershell v5)


### Take Ownership of Powershell Directories
Take ownership of directory, and remove all users from folders.

```C:\Program Files (x86)\WindowsPowerShell
C:\Program Files\WindowsPowerShell
C:\Windows\System32\WindowsPowerShell
C:\Windows\SysWOW64\WindowsPowerShell
``` 

## Random Stuff

**Group Policy Stuff**
Rename Guest and Administrator Accounts
Store password using reversible encryption => Disabled
Change System Time => Administrators
Create Global Objects => Administrators

Security Options
Do not allow enumeration of SAM accounts and Shares
Digitally sign server communication when possible => enabled
Do not display last user name in logon screen => Enabled 
Lan Manager Auth Level => Send LM & NTLM - use NTLMv2 if negotiated 
Number of previous Logons to cache => 0 


**file system perms**
- `C:\`
    - => Administrators Full control
     - => Users/Rest Read & Execute Only
- `C:\Program Files`
    - Administrators -> Full Control
    - Users/Rest -> Read & Execute Only
- `%systemroot%\repair`
    - Administrators/System -> Full control 
    - Deny ISUR & IWAM to -> No ACCESS
- `%systemroot%\security`
    - Administrators/System -> Full Control
    - Remove all else 
- `%systemroot%\system32\config`
    - Administrators/System -> Full control
    - IUSR/IWAM/rest -> No access
- `%systemroot%\system32\dllcache`
    - Administrator/System -> Full Control 
- `%systemroot5\system32\logfiles`
    - Administrators/System -> Full control 

These should be the defaults for Win2k3+ 


Every binary in the system32 folder should be denied for web service accounts etc...

Remove/rename uneeded/unused binaries if possible

### Disable Default Services 

- Alerter 
- Automatic Updates
- Background Inteligent Transfer Service (BITS)
- Clipbook 
- Distributed file System
- Distributed Link Tracking Client
- Distributed Tracking Server 
- Fax Service
- File Replication 
- Indexing Service
- Internet Connecting Sharing 
- Messenger 
- Net Meeting Remote Sharing
- Network DDE 
- Network DSDM
- QoS RSVP
- Remote Access Auto Connection Manager
- Removeable Storage
- RunAs Service (Care)
- Smart Card
- Smart Card Helper
- Telnet

## Resetting Forgotten MySQL Password 
1) Stop MySQL Service
2) Go to the MySQL Bin Folder/wherever MySQL is installed.
3) Run the following command
    - `mysqld.exe -u root --skip-grant-tables` 
4) Leave CMD window as it is, open new command prompt 
5) Run: `mysql`
6) Do the following steps in mysql prompt:
    - `use mysql`
    - `UPDATE user SET Password = PASSWORD('your_new_passowrd') WHERE User = 'root';`
    - `exit`
7) Start MySQL again. 
8) Don't forget to delete/flush mysql history/logs

## Securing PHP on Windows 
1) Modify these settings in the php.ini file.
2) Most important functions to disable are: shell_exec, exec, system, phpinfo, proc_open, popen, allow_url_include, allow_url_fopen, passthru
    3) If you want to be cheesy: base64_decode
4) Full config below
```
file_uploads = Off
disable_functions = "shell_exec, exec, system, phpinfo, proc_open"
allow_url_fopen = Off
expose_php = Off
error_reporting = E_ALL
display_error = Off
display_startup_errors = Off

```
4) All Dangerous Functions to disable
```
disable_functions = "
php_uname, getmyuid, getmypid, passthru, 
leak, listen, diskfreespace, tmpfile, link, 
ignore_user_abord, shell_exec, dl, set_time_limit, exec, 
system, highlight_file, source, show_source, fpaththru, 
virtual, posix_ctermid, posix_getcwd, posix_getegid, 
posix_geteuid, posix_getgid, posix_getgrgid, posix_getgrnam, posix_getgroups, 
posix_getlogin, posix_getpgid, 
posix_getpgrp, posix_getpid, posix, _getppid, 
posix_getpwnam, posix_getpwuid, posix_getrlimit, 
posix_getsid, posix_getuid, posix_isatty, posix_kill, 
posix_mkfifo, posix_setegid, posix_seteuid,
posix_setgid, posix_setpgid, posix_setsid,
posix_setuid, posix_times, posix_ttyname, posix_uname, proc_open, proc_close, 
proc_get_status, proc_nice, proc_terminate, phpinfo"
```
## IIS Preventing Execution of Scripts

- Add this `web.config` file to a directory which you don't want handlers(php, asp, etc...) to execute. 
- Makes all handlers read-only, but not execute

```
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read"/>
  </system.webServer>
</configuration>
```

### IIS Disable use of the Command Shell 

- regedit.exe
    - HKEY_Local_Machine\System\CurrentControlSet\Services\W3SVC\Parameters
        - Value: SSIEnableCMDDirective
            - Value: REG_DWORD =>  0

## Disable WebDAV

- regedit
    - HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters
        - Key Value: DisableWebDav
            - Value: REG_DWORD => 1

### Other Patches to install 
 
- KB2871997 - Enhanced Security & Pth Mitigations for Win7,2008R2
    - https://www.microsoft.com/en-us/download/details.aspx?id=42745

References: 
[Link](https://arno0x0x.wordpress.com/2017/11/20/windows-oneliners-to-download-remote-payload-and-execute-arbitrary-code/)


# Quick Commands for shit 

- Find all unquoted services (EoP)
    - `wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\\windows\\\" |findstr /i /v """` 
    - If any shit appears go into `HKLM\\SYSTEM\\CurrentControlSet\\services` & fix it 

- Enable LSA Protected Mode (8.1 + 2012 R2)
    - `reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL /t REG_SZ /d 1`
    - Restart the computer to apply

- Disable Windows Script Host (vbs,wscript,csript - all that bad shit you feel)
    - `reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Script Host\Settings" /v Enabled /t REG_DWORD /d 0 /f` 

- Disable WDigest (Win7, 8 and Server 2008 R2-2012 - Prevents cleartext creds from being dumped via wdigest)
    *  `reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0`
        - Install KB2871997 patch first 

- Disable WMI 
    - `REG add "HKLM\SYSTEM\CurrentControlSet\services\Winmgmt" /v Start /t REG_DWORD /d 4 /f` 

- Disable the SMB Service
    - `net stop server`

- Remote Desktop Restricted Admin (Windows 8.1+/2012)
    - `mstsc /restrictedadmin` 
