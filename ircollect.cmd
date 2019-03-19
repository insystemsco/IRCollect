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
SET ST=%time%
SETLOCAL EnableDelayedExpansion
COLOR 0a
CLS
chcp 65001>nul 

:: Detect System Architecture
if "%PROCESSOR_ARCHITECTURE%" == "x86" set arch=32
if "%PROCESSOR_ARCHITECTURE%" == "AMD64" set arch=64

:: check_Permissions
    net session >nul 2>>&1
    if %errorLevel% EQU 0 (GOTO admin) ELSE (GOTO notadmin)

:notadmin
echo !!! Administrative permissions not detected !!! >> %logfile%
Echo !!!You must run this as an Administrator!!! >> %logfile%
goto end

:: set storage locations
set cdrive=C:\%computername%\
set logfile=%cdrive%%computername%sysInfo.txt
:: uncomment to have the files moved for processing.
::set offload=someserver\c$

:Admin
REM make storage folders
if not exist %cdrive%%computername% (
	echo:
	mkdir %cdrive%%computername%log
	echo:
	mkdir %cdrive%%computername%preserved-files\
	)

:: Check logfile existance
if EXIST %logfile%. (
    ECHO Warning: File exists. 
    ECHO Appending information...
) ELSE (
    ECHO File created. 
    ECHO Appending information...
)

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
netsh firewall show config >> %logfile% 2>&1

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
mkdir %cdrive%%computername%\log\user\
query user |more >> %cdrive%%computername%\log\user\currentuser.log 2>&1
net user |more >> %cdrive%%computername%\log\user\users.log 2>&1
net localgroup Administrators |more >> %cdrive%%computername%\log\user\localadmins.log 2>&1
logonsessions.exe /accepteula /nobanner |more >> %cdrive%%computername%\log\user\active-sessions.log 2>&1
certutil -store CA |more >> %cdrive%%computername%\log\user\certificates.log 2>&1
certutil -store Root |more >> %cdrive%%computername%\log\user\certificates.log 2>&1

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

:: ending basic sysInfo

REM Windows Firewall details and logs
mkdir %cdrive%%computername%log\network
netsh advfirewall firewall show rule name=all |more >> %cdrive%%computername%log\network\firewall.log 2>&1
netsh advfirewall show global |more >> %cdrive%%computername%log\network\firewall.log 2>&1
netsh advfirewall show allprofiles |more >> %cdrive%%computername%log\network\firewall.log 2>&1
netsh advfirewall dump |more >> %cdrive%%computername%log\network\firewall.log 2>&1
netsh advfirewall firewall dump |more >> %cdrive%%computername%log\network\firewall.log 2>&1
netsh advfirewall firewall show rule name=all verbose |more >> %cdrive%%computername%log\network\firewall.log 2>&1
netsh advfirewall firewall show logging |more >> %cdrive%%computername%log\network\firewall.log 2>&1
robocopy %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log %cdrive%%computername%log\network\ /ZB /copy:DAT /r:0 /ts /FP /np /E 
robocopy %SystemRoot%\System32\LogFiles\HTTPERR\httperr*.log cdrive%%computername%log\network\ /ZB /copy:DAT /r:0 /ts /FP /np /E 
cports.exe /shtml "" /sort 1 /sort ~"Remote Address" >> %cdrive%%computername%\log\network\remoteaddress.html
netstat -abfo |more >> %cdrive%%computername%\log\network\nb-net.log 2>&1
netstat -anob |more >> %cdrive%%computername%\log\network\nb-net.log 2>&1

REM GPO
mkdir %cdrive%%computername%log\user\group-policy\
gpresult /Z > %cdrive%%computername%log\user\group-policy\group-policy-RSoP.txt

REM browser history and addons
BrowsingHistoryView.exe /HistorySource 1 /VisitTimeFilterType 1 /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 1 /sort ~2 /scomma %cdrive%%computername%log\user\history.csv
BrowserAddonsView.exe /sort Name /scomma %cdrive%%computername%log\user\browseraddons.csv

REM File system details
mkdir %cdrive%%computername%log\filesystem\
streams.exe /accepteula /nobanner -s %SystemRoot%  |more >> %cdrive%%computername%log\filesystem\streams-windows.log 2>&1
streams.exe /accepteula /nobanner -s %UserProfile% |more >> %cdrive%%computername%log\filesystem\streams-userprofiles.log 2>&1
sigcheck.exe /accepteula /nobanner -a -e -h -q -u -vt -v %UserProfile% |more >> %cdrive%%computername%log\filesystem\sig-userprofiles.log 2>&1
sigcheck.exe /accepteula /nobanner -a -e -h -q -u -vt -v %SystemRoot% |more >> %cdrive%%computername%log\filesystem\sig-windows.log 2>&1
sigcheck.exe /accepteula /nobanner -a -e -h -q -u -vt -v %SystemRoot%\system32 |more >> %cdrive%%computername%log\filesystem\streams-windows.log 2>&1

REM check for hidden files and folders
dir /S /B /AHD |more >> %cdrive%%computername%\log\drive\hidden.log 2>&1
attrib /D /L /S |more >> %cdrive%%computername%\log\drive\hidden.log 2>&1
dir /S /O-D |more >> %cdrive%%computername%\filesystem |more >> %cdrive%%computername%\filesystem.log 2>&1

REM open file details
openedfilesview.exe /stext >>  %cdrive%%computername%\log\share\openfiles.log 2>&1 
psfile.exe /accepteula /nobanner |more >> %cdrive%%computername%\log\share\remote-openfiles.log 2>&1 

REM processes,services and open handles
mkdir %cdrive%%computername%log\services
pslist.exe /accepteula /nobanner-t |more >> %cdrive%%computername%log\services\tasks-fulldetails.log 2>&1
listdlls.exe /accepteula /nobanner |more >> %cdrive%%computername%log\services\process-dependencies.log 2>&1
handle.exe -asu /accepteula /nobanner |more >> %cdrive%%computername%log\services\openhandles.log 2>&1
autorunsc.exe /accepteula /nobanner -a dehiklst -h -m -s -u |more >> %cdrive%%computername%log\services\autoruns.log 2>&1

REM Look at startup registry entries - to check if anything has been added
mkdir %cdrive%%computername%log\registry
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" |more >> %cdrive%%computername%log\registry\reg-run.log 2>&1
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce" |more >> %cdrive%%computername%log\registry\reg-runonce.log 2>&1
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunonceEx" |more >> %cdrive%%computername%log\registry\reg-runonce.log 2>&1

REM trusted sites - to check if anything has been added
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMapKey" |more >> %cdrive%%computername%log\registry\trusted-sites.log 2>&1

REM the SAM, SECURITY, SOFTWARE, and SYSTEM registry hives
if %arch% == 32 (
			RawCopy.exe %WINDIR%\System32\config\SAM %cdrive%%computername%log\registry\
			RawCopy.exe %WINDIR%\System32\config\SECURITY %cdrive%%computername%log\registry\
			RawCopy.exe %WINDIR%\System32\config\SOFTWARE %cdrive%%computername%log\registry\
			RawCopy.exe %WINDIR%\System32\config\SYSTEM %cdrive%%computername%log\registry\
			)
		if %arch% == 64 (
			RawCopy64.exe %WINDIR%\System32\config\SAM %cdrive%%computername%log\registry\
			RawCopy64.exe %WINDIR%\System32\config\SECURITY %cdrive%%computername%log\registry\
			RawCopy64.exe %WINDIR%\System32\config\SOFTWARE %cdrive%%computername%log\registry\
			RawCopy64.exe %WINDIR%\System32\config\SYSTEM %cdrive%%computername%log\registry\
			)

REM Last 100 Entries from each primary log
mkdir %cdrive%%computername%collection.log 2>&1
WMIC nteventlog list full |more >> %cdrive%%computername%log\eventlog\eventlog
wevtutil.exe qe Security /count:100 /rd:true /format:text |more >> %cdrive%%computername%log\eventlog\security.log 2>&1
wevtutil.exe qe System /count:100 /rd:true /format:text |more >> %cdrive%%computername%log\eventlog\system.log 2>&1
wevtutil.exe qe Application /count:100 /rd:true /format:text |more >> %cdrive%%computername%log\eventlog\application.log 2>&1

REM prefetch files
mkdir %cdrive%%computername%preserved-files\Prefetch\ 
robocopy %WINDIR%\Prefetch %cdrive%%computername%preserved-files\Prefetch\ *.pf /ZB /copy:DAT /r:0 /ts /FP /np /E

REM windows logs
mkdir %cdrive%%computername%preserved-files\winlogs\
robocopy %SYSTEMDRIVE%\Windows\Logs\ %cdrive%%computername%preserved-files\winlogs\ /ZB /copy:DAT /r:0 /ts /FP /np /E 

::
:: run WMI_Forensics against these to check for persistences https://github.com/insystemsco/WMI_Forensics
::
REM WBEM repository - 
mkdir %cdrive%%computername%preserved-files\wmi-repository\
if not exist %SystemRoot%\system32\wbem\Repository\ goto wbem2
robocopy %SystemRoot%\system32\wbem\Repository\ %cdrive%%computername%preserved-files\wmi-repository\ /ZB /copy:DAT /r:0 /ts /FP /np /E 
:wbem2
robocopy %SystemRoot%\system32\wbem\Repository\FS\ %cdrive%%computername%preserved-files\wmi-repository\ /ZB /copy:DAT /r:0 /ts /FP /np /E 

REM memory dumps
if not exist %SystemRoot%\memory.dmp goto copy dump2
if %arch% == 32 (RawCopy.exe "%SystemRoot%\*.DMP" %cdrive%%computername%preserved-files\memory-dumps) else (RawCopy64.exe "%%SystemRoot%\*.DMP" %cdrive%%computername%preserved-files\memory-dumps)
:dump2
if %arch% == 32 (RawCopy.exe "%SystemRoot%\Minidump\*.DMP" %cdrive%%computername%preserved-files\memory-dumps) else (RawCopy64.exe "%SystemRoot%\Minidump\*.DMP" %cdrive%%computername%preserved-files\memory-dumps)

REM App CrashDumps
IF EXIST "C:\Users\" (
    for /D %%x in ("C:\Users\*") do (
if %arch% == 32 (RawCopy.exe "%username%\local\CrashDumps\*.dmp" %cdrive%%computername%preserved-files\memory-dumps) else (RawCopy64.exe " "%username%\local\CrashDumps\*.dmp" %cdrive%%computername%preserved-files\memory-dumps)
)

REM NTUSER.DAT
mkdir %cdrive%%computername%preserved-files\NTUSER_DAT
if %arch% == 32 (RawCopy.exe "%USERPROFILE%\NTUSER.DAT" %cdrive%%computername%preserved-files\NTUSER_DAT) else (RawCopy64.exe "%USERPROFILE%\NTUSER.DAT" %cdrive%%computername%preserved-files\NTUSER_DAT)

REM Copy UsrClass.dat
IF EXIST "C:\Users\" (
    for /D %%x in ("C:\Users\*") do (
	if %arch% == 32 (rawcopy.exe %%x\AppData\Local\Microsoft\Windows\UsrClass.dat %cdrive%%computername%preserved-files\NTUSER_DAT) else (RawCopy64.exe "%USERPROFILE%\NTUSER.DAT" %cdrive%%computername%preserved-files\NTUSER_DAT)
)

REM recent file cache
mkdir %cdrive%%computername%preserved-files\AppCompat\
if %arch% == 32 (RawCopy.exe %WINDIR%\AppCompat\Programs\RecentFileCache.bcf %cdrive%%computername%preserved-files\AppCompat) else (RawCopy64.exe %WINDIR%\AppCompat\Programs\RecentFileCache.bcf %cdrive%%computername%preserved-files\AppCompat)

if %arch% == 32 (RawCopy.exe %SystemRoot%\AppCompat\Programs\Amcache.hve %cdrive%%computername%preserved-files\AppCompat) else (RawCopy64.exe %SystemRoot%\AppCompat\Programs\Amcache.hve %cdrive%%computername%preserved-files\AppCompat)

REM host files
mkdir %cdrive%%computername%log\network\hosts\
if %arch% == 32 (
			RawCopy.exe %WINDIR%\System32\drivers\etc\hosts\ %cdrive%%computername%log\network\hosts\
			)
		if %arch% == 64 (
			RawCopy64.exe %WINDIR%\System32\drivers\etc\hosts\ %cdrive%%computername%log\network\hosts\
			)

REM SRUM collection
mkdir %cdrive%%computername%srumdump\
if %arch% == 32 (RawCopy.exe %WINDIR%\System32\sru\SRUDB.dat %cdrive%%computername%srumdump\ else (RawCopy64.exe %WINDIR%\System32\sru\SRUDB.dat %cdrive%%computername%srumdump\)

REM Run SRUM Dump
srum_dump.exe -i %cdrive%%computername%srumdump\SRUDB.dat -o %cdrive%%computername%srumdump\%computername%.xlsx -t %cdrive%%computername%srumdump\SRUM_TEMPLATE.xlsx

REM Scans all running processes. Recognizes and dumps a variety of potentially malicious implants (replaced/implanted PEs, shellcodes, hooks, in-memory patches). 
mkdir %cdrive%%computername%\hunter
hollows_hunter.exe /hooks /shellc /dmode 0 /uniqd /dir %cdrive%%computername%\hunter

REM memory image
mkdir %cdrive%%computername%preserved-files\memory\
winpmem.exe %cdrive%%computername%preserved-files\memory\physmem.raw -p

:: End - write out data and time
echo %DATE% %TIME% - Exiting collection script and stopping logging for computer %COMPUTERNAME% |more >> %cdrive%%computername%Collection.log 2>&1
:: create zip file of collected data
7za.exe a -tzip %computername%.zip a %cdrive%%computername%
REM move collected files to tanium or other server for review.
::xcopy %computername%.zip \\%tanium% /E /I /C /Y /Z
ENDLOCAL
:end
exit
