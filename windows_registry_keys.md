## Registry Keys
DISCLAIMER: Not all of the following may be present on every version of Windows.
* How to query registry keys
    - autoruns
    - regedit
    - REG QUERY

* Run Keys & Startup Folder

```
\HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\
\HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\
\HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\
\HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices\
\HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce\
\HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\

\HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\
\HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\
\HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices\
\HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce\
\HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\ 
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\

HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\
```
* AppCert DLLs
    - Loaded into any process that calls CreateProcess, CreateProcessAsUser, CreateProcessWithLoginW, CreateProcessWithTokenW, WinExec
```
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager
```
* AppInit DLLs
    - Loaded by every process that uses user32.dll (almost all). Disabled in Windows 8+ if secure boot is enabled.
```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows
HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows
```

* Default File Associations
    - Can be used to run an arbitrary program when certain file extentions are opened. This key overrides default associations.
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts
```

* Component Object Model (COM) Hijacking
    - User objects in this key will override machine objects in HKLM.
```
HKEY_CURRENT_USER\Software\Classes\CLSID\
```

* Netsh Helper DLLs
    - Executes helper DLLs when executed which are registered at this key.
```
HKLM\SOFTWARE\Microsoft\Netsh
```

* Port Monitors
    - Should only contain Appmon, Local Port, Microsoft Shared Fax Monitor, Standard TCP/IP Port, USB Monitor, WSD Port. Can be used to load arbitrary DLLs at startup, will run as SYSTEM.
```
HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors
```

* Screensavers
     - More than just bubbles and ribbons. Check SCRNSAVE.exe, make sure ScreenSaveIsSecure == 1.
```
HKCU\Control Panel\Desktop\
```

* Security Support Provider (SSP) DLLs
    - Loaded into LSA at startup or when AddSecurityPackage is called. Let's red team see plaintext creds.
```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages
```
On Windows 8.1 & Server 2012R2, change AuditLevel to 8 to to require SSP DLLs to be signed.
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe
```

* Password Filters
    - Used to harvest creds anytime a password is changed. Should only contain sceli & rassfm as notification Packages.
```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification 
```

* Winlogon Helper DLL
    - Handles actions at logon/logoff.
```
HKLM\Software[Wow6432Node]Microsoft\Windows NT\CurrentVersion\Winlogon\
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\
...\\Winlogon\Notify
...\\Winlogon\Userinit
...\\Winlogon\Shell
```

* Services
    - Service configuration info is stored in keys in this folder. Monitor and inspect as needed.
```
HKLM\SYSTEM\CurrentControlSet\Services
```
