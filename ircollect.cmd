@ECHO off
::
:: Link: https://github.com/insystemsco/IRCollect/
::
:: Provided as-is with no warranty.
:: Licensed under the GPLv3 - https://www.gnu.org/licenses/gpl-3.0.en.html
::
::
:: Requires:
:: Windows 7 or higher and admin rights.
::
:: Tools:
:: systernals - https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite
:: rawcopy - https://github.com/jschicht/RawCopy
:: winpmem - https://github.com/insystemsco/IR_Collect
:: openedfilesview.exe - https://www.nirsoft.net/utils/opened_files_view.html
:: mmls.exe - https://github.com/insystemsco/IR_Collect
:: Browser History View - https://www.nirsoft.net/utils/browsing_history_view.html
:: Browser Addon View - https://www.nirsoft.net/utils/web_browser_addons_view.html
:: Cports - http://www.nirsoft.net/utils/cports.html
:: 7zip - https://www.7-zip.org/
:: Hollows Hunter https://github.com/hasherezade/hollows_hunter
::
:: Note:
:: Tools need to be in the same directory as the script. All tools are in archive tools.zip
::
::
@echo off
:: check for administartor rights
    net session >nul 2>>&1
    if %errorLevel% EQU 0 (GOTO admin) ELSE (GOTO notadmin)

:notadmin
echo !!!Administrative permissions not detected!!!
Echo !!!You must run this as an Administrator!!!
exit /B 1

:Admin
::set variables
SETLOCAL ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION
SET systemdrive=C:\
SET interactive=0
SET ST=%time%
SET irc=%~n0
SET parent=%~dp0
COLOR 0a
chcp 65001>nul
:tee
ECHO %* >> "%collectionlog%"
ECHO %*
exit /B 0
ECHO %CMDCMDLINE% | FINDSTR /L %COMSPEC% >NUL 2>&1
IF %ERRORLEVEL% == 0 SET interactive=1

:: Detect System Architecture
if "%PROCESSOR_ARCHITECTURE%" == "x86" set arch=32
if "%PROCESSOR_ARCHITECTURE%" == "AMD64" set arch=64

:: set storage locations 
set cdrive=c:\%computername%\
set collection=%cdrive%%collection%\
set preserved=%preserved%\

::set logging locations
set logfile=%cdrive%SystemInfo.txt
set collectionlog=%cdrive%%irc%.%DATE:~10,4%_%DATE:~4,2%_%DATE:~7,2%%TIME:~0,2%_%TIME:~3,2%_%TIME:~6,2%.log
::Uncomment this line to have the files moved. You do not need the \\ in front of of the sever or IP address.
rem set offload=someserver\c$\gatherer

call :tee
REM make storage folders
if not exist %cdrive% (
	mkdir %cdrive%collection
	mkdir %cdrive%preserved
	)

::hide colletion folders from users
attrib +s +h %cdrive%

:: Collect basic system information
REM Date
ECHO ============= >> %logfile%
ECHO === Log created at: >> %logfile%
ECHO ============= >> %logfile%
ECHO Date and time: >> %logfile% 
ECHO %date%-%time% >> %logfile% 2>&1
ECHO Timezone: >> %logfile% 
wmic Timezone get DaylightName,Description,StandardName |more >> %logfile% 2>&1

REM Basic Information
ECHO ============= >> %logfile%
ECHO === Basic Information: >> %logfile%
ECHO ============= >> %logfile%
ECHO Output of whoami: >> %logfile%
whoami >> %logfile% 2>&1
ECHO Output of %^%username%^%: >> %logfile% 
ECHO %username% >> %logfile% 2>&1
ECHO Output of %^%computername%^%: >> %logfile% 
ECHO %computername% >> %logfile% 2>&1

REM Net Users
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === Net Users: >> %logfile%
ECHO ============= >> %logfile%
net users >> %logfile% 2>&1

REM Environment Variables
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === Environment Variables: >> %logfile%
ECHO ============= >> %logfile%
ECHO Output of SET: >> %logfile% 
set >> %logfile% 2>&1
ECHO Output of %^%cmdextversion%^%: >> %logfile% 
echo %cmdextversion% >> %logfile% 2>&1
ECHO Output of %^%cmdcmdline%^%: >> %logfile% 
echo %cmdcmdline% >> %logfile% 2>&1
ECHO Output of %^%errorlevel%^%: >> %logfile% 
echo %errorlevel% >> %logfile% 2>&1

REM Full Systeminfo
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === Full Systeminfo: >> %logfile%
ECHO ============= >> %logfile%
systeminfo >> %logfile% 2>&1

REM IPConfig
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === IPConfig: >> %logfile%
ECHO ============= >> %logfile%
ipconfig /all >> %logfile% 2>&1

REM Routes
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === Routes: >> %logfile%
ECHO ============= >> %logfile%
route print >> %logfile% 2>&1

REM ARP
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === ARP: >> %logfile%
ECHO ============= >> %logfile%
arp -A >> %logfile% 2>&1

REM Netstat
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === Netstat: >> %logfile%
ECHO ============= >> %logfile%
netstat -ano >> %logfile% 2>&1
net view \\127.0.0.1 >> %logfile% 2>&1

REM Firewall State
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === Firewall State: >> %logfile%
ECHO ============= >> %logfile%
netsh firewall show state >> %logfile% 2>&1

REM Firewall Config
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === Firewall Config: >> %logfile%
ECHO ============= >> %logfile%
mkdir %collection%firewall
netsh firewall show config >> %logfile% 2>&1
echo for more details see %%collection%firewall >> %logfile%
netsh advfirewall firewall show rule name=all |more >> %collection%firewall\firewall.log 2>&1
netsh advfirewall show global |more >> %collection%firewall\firewall.log 2>&1
netsh advfirewall show allprofiles |more >> %collection%firewall\firewall.log 2>&1
netsh advfirewall dump |more >> %collection%firewall\firewall.log 2>&1
netsh advfirewall firewall dump |more >> %collection%firewall\firewall.log 2>&1
netsh advfirewall firewall show rule name=all verbose |more >> %collection%firewall\firewall.log 2>&1
netsh advfirewall firewall show logging |more >> %collection%firewall\firewall.log 2>&1
robocopy %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log %collection%firewall\ /ZB /copy:DAT /r:0 /ts /FP /np /E 
robocopy %SystemRoot%\System32\LogFiles\HTTPERR\httperr*.log cdrive%%computername%%collection%firewall\ /ZB /copy:DAT /r:0 /ts /FP /np /E 

REM Scheduled Tasks
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === Scheduled Tasks: >> %logfile%
ECHO ============= >> %logfile%
schtasks /query /fo LIST /v >> %logfile% 2>&1

REM Processes
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === Processes: >> %logfile%
ECHO ============= >> %logfile%
ECHO Tasklist: >> %logfile% 2>&1
tasklist /SVC >> %logfile% 2>&1
ECHO WMIC: >> %logfile% 2>&1
wmic process get CSName,Description,ExecutablePath,ProcessId |more >> %logfile% 2>&1

REM Services
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === Services: >> %logfile%
ECHO ============= >> %logfile%
ECHO Net: >> %logfile% 2>&1
net start >> %logfile% 2>&1
ECHO WMIC: >> %logfile% 2>&1
wmic service get Caption,Name,PathName,ServiceType,Started,StartMode,StartName |more >> %logfile% 2>&1
schtasks /query /fo LIST /v >> %logfile% 2>&1
tasklist /FO TABLE >> %logfile% 2>&1
tasklist /FO TABLE /SVC >> %logfile% 2>&1

REM Driver Information
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === Driver Information: >> %logfile%
ECHO ============= >> %logfile%
DRIVERQUERY >> %logfile% 2>&1

REM Windows Updates Information
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === Windows Updates Information: >> %logfile%
ECHO ============= >> %logfile%
wmic qfe get Caption,Description,HotFixID,InstalledOn |more >> %logfile% 2>&1

REM %path%
ECHO ============= >> %logfile%
ECHO === Output of %^%path%^%: >> %logfile%
ECHO ============= >> %logfile%
ECHO %path% >> %logfile% 2>&1

REM Useraccount info
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === Useraccount SID: >> %logfile%
ECHO ============= >> %logfile%
query user |more >> %collection%user\currentuser.log 2>&1
net user |more >> %collection%user\users.log 2>&1
net localgroup Administrators |more >> %collection%localadmins.log 2>&1
logonsessions.exe /accepteula /nobanner |more >> %collection%active-sessions.log 2>&1
certutil -store CA |more >>%collection%certificates.log 2>&1
certutil -store Root |more >> %collection%certificates.log 2>&1

REM Service Pack Information
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === Service Pack Information: >> %logfile%
ECHO ============= >> %logfile%
wmic os get ServicePackMajorVersion /value |more >> %logfile% 2>&1

REM  Drives
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === Drives: >> %logfile%
ECHO ============= >> %logfile%
ECHO System Drive: >> %logfile% 2>&1
ECHO %systemdrive% >> %logfile% 2>&1
ECHO All drives: >> %logfile% 2>&1
fsutil fsinfo drives >> %logfile% 2>&1
ECHO System drive type: >> %logfile% 2>&1
fsutil fsinfo driveType %systemdrive% >> %logfile% 2>&1
ECHO WMIC: >> %logfile% 2>&1
wmic volume get Label,DeviceID,DriveLetter,FileSystem,Capacity,FreeSpace |more >> %logfile% 2>&1
ntfsinfo.exe -nobanner -accepteula %cdrive% >> %logfile%

REM CPU
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === CPU: >> %logfile%
ECHO ============= >> %logfile%
ECHO Architecture: >> %logfile% 2>&1
ECHO %processor_architecture% >> %logfile% 2>&1
ECHO WMIC: >> %logfile% 2>&1
wmic CPU get Description, DeviceID, Manufacturer, MaxClockSpeed, Name, Status, SystemName |more >> %logfile% 2>&1

REM Network Shares
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === Network Shares: >> %logfile%
ECHO ============= >> %logfile%
wmic netuse list |more >> %logfile% 2>&1
net view \\127.0.0.1 |more >> %logfile% 2>&1

REM Startup
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === Startup: >> %logfile%
ECHO ============= >> %logfile%
wmic startup get Caption,Command,Location,User |more >> %logfile% 2>&1

REM OS
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === OS: >> %logfile%
ECHO ============= >> %logfile%
wmic os get name,version,InstallDate,LastBootUpTime,LocalDateTime,Manufacturer,RegisteredUser,ServicePackMajorVersion,SystemDirectory |more >> %logfile% 2>&1

REM NIC
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === NIC: >> %logfile%
ECHO ============= >> %logfile%
wmic nicconfig where IPEnabled='true' get Caption,DefaultIPGateway,Description,DHCPEnabled,DHCPServer,IPAddress,IPSubnet,MACAddress |more >> %logfile% 2>&1
netsh bridge show adapter |more >> %logfile% 2>&1
netsh bridge dump |more >> %logfile% 2>&1
netsh mbn show interface |more >> %logfile% 2>&1
netsh interface dump |more >> %logfile% 2>&1
netsh interface portproxy show all |more >> %logfile% 2>&1

REM Products
ECHO. >> %logfile%
ECHO ============= >> %logfile%
ECHO === Products: >> %logfile%
ECHO ============= >> %logfile%
wmic PRODUCT get Description,InstallDate,InstallLocation,PackageCache,Vendor,Version |more >> %logfile% 2>&1

:: ending basic sysInfo - begin forensics

REM Current connections
cports.exe /shtml "" /sort 1 /sort ~"Remote Address" >> %collection%network\remoteaddress.html

REM collect host files
mkdir %collection%network\hostsfiles\
if %arch% == 32 (
			RawCopy.exe %WINDIR%\System32\drivers\etc\hosts\ %collection%network\hostsfiles\
			)
		else (
			RawCopy64.exe %WINDIR%\System32\drivers\etc\hosts\ %collection%network\hostsfiles\
			)

REM GPO report
gpresult /Z > %collection%gpRSoP.txt

REM browser history and addons
BrowsingHistoryView.exe /HistorySource 1 /VisitTimeFilterType 1 /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 1 /sort ~2 /scomma %collection%browserhistory.csv
BrowserAddonsView.exe /sort Name /scomma %collection%browseraddons.csv

REM File system details
streams.exe /accepteula /nobanner -s %SystemRoot% |more >> %collection%streams-windows.log 2>&1
streams.exe /accepteula /nobanner -s %UserProfile% |more >> %collection%streams-userprofiles.log 2>&1
sigcheck.exe /accepteula /nobanner -a -e -h -q -u -vt -v %UserProfile% |more >> %collection%sig-userprofiles.log 2>&1
sigcheck.exe /accepteula /nobanner -a -e -h -q -u -vt -v %SystemRoot% |more >> %collection%sig-windows.log 2>&1
sigcheck.exe /accepteula /nobanner -a -e -h -q -u -vt -v %SystemRoot%\system32 |more >> %collection%streams-windows.log 2>&1

REM check for hidden files and folders
dir %systemdrive%\ /O /S /B /AHD |sort |more >> %collection%hiddenfiles.log 2>&1
attrib /D /L /S |more >> %collection%attribs.log 2>&1

REM open file details
openedfilesview.exe /stext >> %collection%openfiles.log 2>&1 
psfile.exe /accepteula /nobanner |more >> %collection%remote-openfiles.log 2>&1 

REM processes,services and open handles
pslist.exe /accepteula /nobanner-t |more >> %collection%running-fulldetails.log 2>&1
listdlls.exe /accepteula /nobanner |more >> %collection%process-dependencies.log 2>&1
handle.exe -asu /accepteula /nobanner |more >> %collection%openhandles.log 2>&1
autorunsc.exe /accepteula /nobanner -a dehiklst -h -m -s -u |more >> %collection%autoruns.log 2>&1

REM Look at startup registry entries - to check if anything has been added
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" |more >> %collection%registry-run.log 2>&1
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce" |more >> %collection%registry-runonce.log 2>&1
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunonceEx" |more >> %collection%registry-runonceex.log 2>&1

REM trusted sites - to check if anything has been added
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMapKey" |more >> %collection%trusted-sites.log 2>&1

REM the SAM, SECURITY, SOFTWARE, and SYSTEM registry hives
mkdir %cdrive%%collection%registryhive
if %arch% == 32 (
			RawCopy.exe %WINDIR%\System32\config\SAM %collection%registryhive\
			RawCopy.exe %WINDIR%\System32\config\SECURITY %collection%registryhive\
			RawCopy.exe %WINDIR%\System32\config\SOFTWARE %collection%registryhive\
			RawCopy.exe %WINDIR%\System32\config\SYSTEM %collection%registryhive\
			)
		else (
			RawCopy64.exe %WINDIR%\System32\config\SAM %collection%registryhive\
			RawCopy64.exe %WINDIR%\System32\config\SECURITY %collection%registryhive\
			RawCopy64.exe %WINDIR%\System32\config\SOFTWARE %collection%registryhive\
			RawCopy64.exe %WINDIR%\System32\config\SYSTEM %collection%registryhive\
			)

REM Last 100 Entries from each primary log
mkdir %collection%eventlog 
WMIC nteventlog list full |more >> %collection%eventlog\eventlog.log
wevtutil.exe qe Security /count:100 /rd:true /format:text |more >> %collection%eventlog\security.log 2>&1
wevtutil.exe qe System /count:100 /rd:true /format:text |more >> %collection%eventlog\system.log 2>&1
wevtutil.exe qe Application /count:100 /rd:true /format:text |more >> %collection%eventlog\application.log 2>&1

REM prefetch files
mkdir %preserved%prefetch\ 
robocopy %WINDIR%\Prefetch %preserved%Prefetch\ *.pf /ZB /copy:DAT /r:0 /ts /FP /np /E

REM windows logs
mkdir %preserved%winlogs
robocopy %SYSTEMDRIVE%\Windows\Logs\ %preserved%winlogs\ /ZB /copy:DAT /r:0 /ts /FP /np /E 

REM WBEM repository - 
echo Run WMI_Forensics against these to check for persistences https://github.com/insystemsco/WMI_Forensics >> %preserved%wmirepo\_readme.txt
mkdir %preserved%wmirepo
if not exist %SystemRoot%\system32\wbem\Repository\ goto wbem2
robocopy %SystemRoot%\system32\wbem\Repository\ %preserved%wmirepo\ /ZB /copy:DAT /r:0 /ts /FP /np /E 
:wbem2
robocopy %SystemRoot%\system32\wbem\Repository\FS\ %preserved%wmirepo\ /ZB /copy:DAT /r:0 /ts /FP /np /E 

REM memory dumps
mkdir %preserved%memory
if not exist %SystemRoot%\memory.dmp goto copy dump2
if %arch% == 32 (RawCopy.exe "%SystemRoot%\*.DMP" %preserved%memory) else (RawCopy64.exe "%SystemRoot%\*.DMP" %cdrive%computername%%preserved%memory)
:dump2
if %arch% == 32 (RawCopy.exe "%SystemRoot%\Minidump\*.DMP" %preserved%memory) else (RawCopy64.exe "%SystemRoot%\Minidump\*.DMP" %preserved%memory)

REM App CrashDumps
For /D %%x in ("C:\Users\*") do if %arch% == 32 (RawCopy.exe "%%x\local\CrashDumps\*.dmp" %preserved%memory) else (RawCopy64.exe "%%x\local\CrashDumps\*.dmp" %preserved%memory)

REM NTUSER.DAT
mkdir %preserved%NTUSER_DAT
For /D %%x in ("C:\Users\*") do if %arch% == 32 (RawCopy.exe "%%x\NTUSER.DAT" %preserved%NTUSER_DAT) else (RawCopy64.exe "%%x\NTUSER.DAT" %preserved%NTUSER_DAT)

REM Copy UsrClass.dat
For /D %%x in ("C:\Users\*") do if %arch% == 32 (rawcopy.exe "%%x\AppData\Local\Microsoft\Windows\UsrClass.dat" %preserved%NTUSER_DAT) else (RawCopy64.exe "%%x\AppData\Local\Microsoft\Windows\UsrClass.dat" %preserved%NTUSER_DAT)

REM recent file cache
mkdir %preserved%recentfiles
if %arch% == 32 (RawCopy.exe %WINDIR%\AppCompat\Programs\RecentFileCache.bcf %preserved%AppCompat) else (RawCopy64.exe %WINDIR%\AppCompat\Programs\RecentFileCache.bcf %preserved%recentfiles\)
if %arch% == 32 (RawCopy.exe %SystemRoot%\AppCompat\Programs\Amcache.hve %preserved%AppCompat) else (RawCopy64.exe %SystemRoot%\AppCompat\Programs\Amcache.hve %preserved%recentfiles\)

REM SRUM collection
mkdir %preserved%srumdump
if %arch% == 32 (RawCopy.exe %WINDIR%\System32\sru\SRUDB.dat %preserved%srumdump\ else (RawCopy64.exe %WINDIR%\System32\sru\SRUDB.dat %preserved%srumdump\)

REM Run SRUM Dump
srum_dump.exe -i %preserved%srumdump\SRUDB.dat -o %cpreserved%%computername%.xlsx -t %preserved%srumdump\SRUM_TEMPLATE.xlsx

REM Scans all running processes. Recognizes and dumps a variety of potentially malicious implants replaced/implanted PEs, shellcodes, hooks, in-memory patches. 
mkdir %collection%hunter
echo Scanning for potentially malicious implants replaced/implanted PEs, shellcodes, hooks, in-memory patches. >>  %collection%hunter\README.txt
hollows_hunter.exe /hooks /shellc /dmode 0 /uniqd /dir %collection%hunter

REM dumping memory image
mkdir %preserved%memory
winpmem.exe %preserved%memory\physmem.raw -p

::list collected data
dir %cdrive% /O /S /B /AHD |sort |more >> %logfile% 2>&1

::preseve collected then move data to remote server and clean up files.
attrib -s -h %cdrive%
7za.exe a -tzip %computername%.zip a %cdrive%
xcopy %cdrive%\%computername%.zip %systemdrive% /E /I /C /Y /Z
:: uncomment this line to have the collected data uploaded.
rem xcopy %cdrive%\%computername%.zip \\%offload% /E /I /C /Y /Z
if exist %systemdrive%%computername%.zip rmdir /s /q %cdrive%

::all done
echo %DATE% %TIME% - Exiting collection script and stopping logging for computer %COMPUTERNAME% |more >> %logfile% 2>&1
ENDLOCAL
:end
IF "%interactive%"=="0" PAUSE
EXIT /B 0
