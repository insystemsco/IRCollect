@echo off
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
::
:: Note:
:: Tools need to be in the same directory as the script. All tools are in archive tools.zip
::
SETLOCAL ENABLEDELAYEDEXPANSION

:: set storage location
set cdrive=C:\

:: Detect System Architecture
if "%PROCESSOR_ARCHITECTURE%" == "x86" set arch=32
if "%PROCESSOR_ARCHITECTURE%" == "AMD64" set arch=64

:: check_Permissions
    net session >nul 2>>&1
    if %errorLevel% EQU 0 (GOTO admin) ELSE (GOTO notadmin)

:notadmin
echo !!! Administrative permissions not detected !!!
echo .
Echo !!!You must run this as an Administrator!!!
echo !!!
echo .
pause
exit

:Admin
REM make storage folders
if not exist %cdrive%%computername% (
	echo:
	mkdir %cdrive%%computername%\log
	echo:
	mkdir %cdrive%%computername%\preserved-files\
	)

REM set log
echo %DATE% %TIME% - Logging initiated for %COMPUTERNAME%
echo %DATE% %TIME% - Logging initiated for %COMPUTERNAME% >> %cdrive%%computername%\Collection.log

REM get windows version and system various details
echo ------IR COLLECT LOG------%DATE% %TIME% >>%cdrive%%computername%\collection.log
WMIC product get Name, Version >> %cdrive%%computername%\collection.log
echo ------------------------------ >>% cdrive%%computername%\collection.log
systeminfo /FO list >> %cdrive%%computername%\collection.log
ipconfig /all >> %cdrive%%computername%\collection.log
echo ------System Hardware Datails------ >> %cdrive%%computername%\collection.log
WMIC bios get  manufacturer, smbiosbiosversion >> %cdrive%%computername%\collection.log
ntfsinfo.exe -nobanner -accepteula %cdrive% >> %cdrive%%computername%\collection.log
echo ------Windows Page file and recovery details------ >> %cdrive%%computername%\collection.log
WMIC pagefile >> %cdrive%%computername%\collection.log
WMIC recoveros >> %cdrive%%computername%\collection.log
echo ------Available Windows Updates------ >> %cdrive%%computername%\collection.log
WMIC qfe >> %cdrive%%computername%\log\collection.log
echo ------Installed Software------ >> %cdrive%%computername%\collection.log 
WMIC product get Name, Version >> %cdrive%%computername%\collection.log

REM grab user details
mkdir %cdrive%%computername%\log\user\
query user >> %cdrive%%computername%\log\user\currentuser.log
wmic Desktop >> %cdrive%%computername%\log\user\desktop.log
net user >> %cdrive%%computername%\log\user\user.log
net localgroup Administrators >> %cdrive%%computername%\log\user\localadmins.log
logonsessions.exe /accepteula /nobanner >> %cdrive%%computername%\log\user\active-sessions.log
certutil -store CA >> %cdrive%%computername%\log\user\certificates.log
certutil -store Root >> %cdrive%%computername%\log\user\certificates.log

REM Get browser history and addons
BrowsingHistoryView.exe /HistorySource 1 /VisitTimeFilterType 1 /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 1 /sort ~2 /scomma %cdrive%%computername%\log\user\history.csv
BrowserAddonsView.exe /sort Name /scomma %cdrive%%computername%\log\user\browseraddons.csv

REM Grab GPO
mkdir %cdrive%%computername%\log\user\group-policy\
gpresult /Z > %cdrive%%computername%\log\user\group-policy\group-policy-RSoP.txt

REM File system details
mkdir %cdrive%%computername%\log\filesystem\
tree %SystemRoot% >> %cdrive%%computername%\log\filesystem\tree-windows.log
tree %UserProfile% >> %cdrive%%computername%\log\filesystem\tree-userprofiles.log
tree %ProgramFiles% >> %cdrive%%computername%\log\filesystem\tree-programfiles.log
tree %ProgramFiles(x86)% %cdrive%%computername%\log\filesystem\tree-programfilesx86.log
streams.exe /accepteula /nobanner -s %SystemRoot%  >> %cdrive%%computername%\log\filesystem\streams-windows.log
streams.exe /accepteula /nobanner -s %UserProfile% >> %cdrive%%computername%\log\filesystem\streams-userprofiles.log
sigcheck.exe /accepteula /nobanner -a -e -h -q -u -vt -v %UserProfile% >> %cdrive%%computername%\log\filesystem\sig-userprofiles.log
sigcheck.exe /accepteula /nobanner -a -e -h -q -u -vt -v %SystemRoot% >> %cdrive%%computername%\log\filesystem\sig-windows.log
sigcheck.exe /accepteula /nobanner -a -e -h -q -u -vt -v %SystemRoot%\system32 >> %cdrive%%computername%\log\filesystem\streams-windows.log

REM systems paths and env
mkdir %cdrive%%computername%\log\systemenvn\
WMIC Path Win32_Environment Where "Name='PATH' And Systemvariable=TRUE" >> %cdrive%%computername%\log\systemenv\systempaths.log
WMIC Path Win32_Environment Where "Name='PATH' And Systemvariable=FALSE" >> %cdrive%%computername%\log\systemenv\systempaths.log
WMIC environment >> %cdrive%%computername%\log\systemenv\environment.log

REM Get  drive details
mkdir %cdrive%%computername%\log\drive
WMIC Path Win32_LogicalDisk Get DeviceID^,Description^,DriveType >> %cdrive%%computername%\log\drive\drive.log
WMIC Path Win32_LogicalDiskToPartition Get Antecedent^,Dependent /Format:list >> %cdrive%%computername%\log\drive\drive.log
mmls.exe \\.\PHYSICALDRIVE0 >> %cdrive%%computername%\log\drive\drive.log 
vssadmin list volumes >> %cdrive%%computername%\log\drive\volumes.log 
vssadmin list shadowstorage >> %cdrive%%computername%\log\drive\shadowstorage.log 
vssadmin list shadows >> %cdrive%%computername%\log\drive\shadows.log 
fsutil usn enumdata 1 0 1 %cdrive%  >> %cdrive%%computername%\log\drive\enumdata.log
fsutil usn readjournal %cdrive%  >> %cdrive%%computername%\log\drive\usnjournal.log
ExtractUSNJrnl.exe /devicepath:%cdrive%  >> %cdrive%%computername%\log\drive\usnjournalextract.log

REM check for hidden files and folders
dir /S /B /AHD >> %cdrive%%computername%\log\drive\hidden.log
attrib /D /L /S >> %cdrive%%computername%\log\drive\hidden.log
dir /S /O-D >> %cdrive%%computername%\filesystem >> %cdrive%%computername%\filesystem.log

REM get share details
WMIC share >> %cdrive%%computername%\log\share\shares.log
openedfilesview.exe /stext >>  %cdrive%%computername%\log\share\openfiles.log 
psfile.exe /accepteula /nobanner >> %cdrive%%computername%\log\share\remote-openfiles.log 

REM Network activities
mkdir %cdrive%%computername%\log\network
ipconfig /all >> %cdrive%%computername%\log\network\net-config.log
ipconfig /displaydns >> %cdrive%%computername%\log\network\dns-net.log
arp -a >> %cdrive%%computername%\log\network\arp-cache.log
netstat -o >> %cdrive%%computername%\log\network\port-to-process-mapping.csv
echo ------Current Net Use sessions------ >> %cdrive%%computername%\log\network\net.log
net view \\127.0.0.1 >> %cdrive%%computername%\log\network\net.log
net sessions >> %cdrive%%computername%\log\network\net.log
net use >> %cdrive%%computername%\log\network\net.log
echo ------Open Ports------ >> %cdrive%%computername%\log\network\nb-net.log
netstat -abfo >> %cdrive%%computername%\log\network\nb-net.log
echo ------Netbios Cache------ >> %cdrive%%computername%\log\network\nb-net.log
nbtstat -c >> %cdrive%%computername%\log\network\nb-net.log
echo ------Netbios Sessions------ >> %cdrive%%computername%\log\network\nb-net.log
nbtstat -S >> %cdrive%%computername%\log\network\nb-net.log
echo ------Active Network Connections------ >> %cdrive%%computername%\log\network\nb-net.log
netstat -anob >> %cdrive%%computername%\log\network\nb-net.log
echo ------NetBIOS Names Resolution and Registration Statistics------ >> %cdrive%%computername%\log\network\nb-net.log
netstat -r >> %cdrive%%computername%\log\network\nb-net.log
cports.exe /shtml "" /sort 1 /sort ~"Remote Address" >> %cdrive%%computername%\log\network\remoteaddress.html

REM Get host files
mkdir %cdrive%%computername%\log\network\hosts\
if %arch% == 32 (
			RawCopy.exe %WINDIR%\System32\drivers\etc\hosts\ %cdrive%%computername%\log\network\hosts\
			)
		if %arch% == 64 (
			RawCopy64.exe %WINDIR%\System32\drivers\etc\hosts\ %cdrive%%computername%\log\network\hosts\
			)



REM Windows Firewall details and logs
netsh interface show interface >> %cdrive%%computername%\log\network\adapters.log
netsh firewall show config >> %cdrive%%computername%\log\network\firewall.log
netsh advfirewall firewall show rule name=all >> %cdrive%%computername%\log\network\firewall.log
netsh firewall show config verbose=enable >> %cdrive%%computername%\log\network\firewall.log
netsh advfirewall show global >> %cdrive%%computername%\log\network\firewall.log
netsh advfirewall show allprofiles >> %cdrive%%computername%\log\network\firewall.log
netsh advfirewall dump >> %cdrive%%computername%\log\network\firewall.log
netsh advfirewall firewall dump >> %cdrive%%computername%\log\network\firewall.log
netsh firewall show allowedprogram verbose=enable >> %cdrive%%computername%\log\network\firewall.log
netsh advfirewall firewall show rule name=all verbose >> %cdrive%%computername%\log\network\firewall.log
netsh advfirewall firewall show logging >> %cdrive%%computername%\log\network\firewall.log
robocopy %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log >> %cdrive%%computername%\log\network\ /ZB /copy:DAT /r:0 /ts /FP /np /E 
robocopy %SystemRoot%\System32\LogFiles\HTTPERR\httperr*.log >> %cdrive%%computername%\log\network\ /ZB /copy:DAT /r:0 /ts /FP /np /E 
netsh bridge show adapter >> %cdrive%%computername%\log\network\bridge.log
netsh bridge dump >> %cdrive%%computername%\log\network\bridge.log
netsh mbn show interface >> %cdrive%%computername%\log\network\mobileadapter.log
netsh interface dump >> %cdrive%%computername%\log\network\interfacedump.log
netsh interface portproxy show all >> %cdrive%%computername%\log\network\protproxy.log

REM Grab processes,services and scheduled tasks
mkdir %cdrive%%computername%\log\services
schtasks /query /fo LIST /v >> %cdrive%%computername%\log\services\scheduled-tasks.log
tasklist /FO TABLE >> %cdrive%%computername%\log\services\task.log
tasklist /FO TABLE /SVC >> %cdrive%%computername%\log\services\task.log
tasklist /M >> %cdrive%%computername%\log\services\task.log
tasklist /SVC >> %cdrive%%computername%\log\services\task.log
pslist.exe /accepteula /nobanner-t >> %cdrive%%computername%\log\services\tasks-fulldetails.log
net start >> %cdrive%%computername%\log\services\startup-services.log
sc query state= all >> %cdrive%%computername%\log\services\services.log
sc query type= interact >> %cdrive%%computername%\log\services\inter-services.log
wmic process get description,executablepath >> %cdrive%%computername%\log\services\running-processes.log
listdlls.exe /accepteula /nobanner >> %cdrive%%computername%\log\services\process-dependencies.log
handle.exe -asu /accepteula /nobanner >> %cdrive%%computername%\log\services\openhandles.log
WMIC startup list full  >> %cdrive%%computername%\startup.log

REM Copy schedule taks log and folder
if %arch% == 32 (RawCopy.exe %WINDIR%\SchedLgU.txt %cdrive%%computername%\log\services\) else (RawCopy64.exe %WINDIR%\SchedLgU.txt %cdrive%%computername%\log\services\)
robocopy %WINDIR%\Tasks %cdrive%%computername%\log\services\ /ZB /copy:DAT /r:0 /ts /FP /np 

:: grab autoruns 
autorunsc.exe /accepteula /nobanner -a dehiklst -h -m -s -u >> %cdrive%%computername%\log\services\autoruns.log

REM Grab loaded drivers
mkdir %cdrive%%computername%\loaded-drivers
sc query type= driver >> %cdrive%%computername%\log\loaded-drivers\drivers.log
WMIC sysdriver list full >> %cdrive%%computername%\log\loaded-drivers\drivers.log
%WINDIR%\System32\driverquery.exe /fo csv /si >> %cdrive%%computername%\log\services\driverdetails.log

REM Look at startup registry entries - to check if anything has been added
mkdir %cdrive%%computername%\log\registry
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" >> %cdrive%%computername%\log\registry\reg-run.log
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce" >> %cdrive%%computername%\log\registry\reg-runonce.log
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunonceEx" >> %cdrive%%computername%\log\registry\reg-runonce.log

REM Grab trusted sites - to check if anything has been added
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMapKey" >> %cdrive%%computername%\log\registry\trusted-sites.log

REM Get known DLLs 
reg query HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs >> %cdrive%%computername%\log\registry\known-dlls.log

REM get running services
reg query HKLM\SYSTEM\CurrentControlSet\Services >> %cdrive%%computername%\log\registry\runningservices.log

REM grab the SAM, SECURITY, SOFTWARE, and SYSTEM registry hives
if %arch% == 32 (
			RawCopy.exe %WINDIR%\System32\config\SAM %cdrive%%computername%\log\registry\
			RawCopy.exe %WINDIR%\System32\config\SECURITY %cdrive%%computername%\log\registry\
			RawCopy.exe %WINDIR%\System32\config\SOFTWARE %cdrive%%computername%\log\registry\
			RawCopy.exe %WINDIR%\System32\config\SYSTEM %cdrive%%computername%\log\registry\
			)
		if %arch% == 64 (
			RawCopy64.exe %WINDIR%\System32\config\SAM %cdrive%%computername%\log\registry\
			RawCopy64.exe %WINDIR%\System32\config\SECURITY %cdrive%%computername%\log\registry\
			RawCopy64.exe %WINDIR%\System32\config\SOFTWARE %cdrive%%computername%\log\registry\
			RawCopy64.exe %WINDIR%\System32\config\SYSTEM %cdrive%%computername%\log\registry\
			)

REM Grab Last 50 Entries from each primary log
mkdir %cdrive%%computername%\collection.log
WMIC nteventlog list full >> %cdrive%%computername%\log\eventlog\eventlog.log nteventlog list full
wevtutil.exe qe Security /count:50 /rd:true /format:text >> %cdrive%%computername%\log\eventlog\security.log
wevtutil.exe qe System /count:50 /rd:true /format:text >> %cdrive%%computername%\log\eventlog\system.log
wevtutil.exe qe Application /count:50 /rd:true /format:text >> %cdrive%%computername%\log\eventlog\application.log

REM copies the eventlog in case we need it later
if %arch% == 32 (
				RawCopy.exe %WINDIR%\System32\winevt\Logs\Application.evtx %cdrive%%computername%\log\eventlog\
				RawCopy.exe %WINDIR%\System32\winevt\Logs\Security.evtx %cdrive%%computername%\log\eventlog\
				RawCopy.exe %WINDIR%\System32\winevt\Logs\System.evtx %cdrive%%computername%\log\eventlog\
			)
			if %arch% == 64 (
				RawCopy64.exe %WINDIR%\System32\winevt\Logs\Application.evtx %cdrive%%computername%\log\eventlog\
				RawCopy64.exe %WINDIR%\System32\winevt\Logs\Security.evtx %cdrive%%computername%\log\eventlog\
				RawCopy64.exe %WINDIR%\System32\winevt\Logs\System.evtx %cdrive%%computername%\log\eventlog\
			)

REM Grab prefetch files
mkdir %cdrive%%computername%\preserved-files\Prefetch\ 
robocopy %WINDIR%\Prefetch %cdrive%%computername%\preserved-files\Prefetch\ *.pf /ZB /copy:DAT /r:0 /ts /FP /np /E

REM Grab windows logs
mkdir %cdrive%%computername%\preserved-files\winlogs\
robocopy %SYSTEMDRIVE%\Windows\Logs\ %cdrive%%computername%\preserved-files\winlogs\ /ZB /copy:DAT /r:0 /ts /FP /np /E 

REM Malicious Software Removal Toolkit logs
mkdir %cdrive%%computername%\preserved-files\debug\
robocopy %cdrive%%computername%\preserved-files\debug\ /ZB /copy:DAT /r:0 /ts /FP /np /E 

REM grab WBEM repository - 
mkdir %cdrive%%computername%\preserved-files\wmi-repository\
::
:: run WMI_Forensics against these to check for persistences https://github.com/insystemsco/WMI_Forensics
::
if not exist %SystemRoot%\system32\wbem\Repository\ goto wbem2
robocopy %SystemRoot%\system32\wbem\Repository\ %cdrive%%computername%\preserved-files\wmi-repository\ /ZB /copy:DAT /r:0 /ts /FP /np /E 
:wbem2
robocopy %SystemRoot%\system32\wbem\Repository\FS\ %cdrive%%computername%\preserved-files\wmi-repository\ /ZB /copy:DAT /r:0 /ts /FP /np /E 

REM grab memory dumps
if not exist %SystemRoot%\memory.dmp got copy memory2
robocopy %SystemRoot%\MEMORY.DMP %cdrive%%computername%\preserved-files\memory-dumps\ /ZB /copy:DAT /r:0 /ts /FP /np /E 
:memory2
robocopy %SystemRoot%\Minidump\ %cdrive%%computername%\preserved-files\memory-dumps\ /ZB /copy:DAT /r:0 /ts /FP /np /E
robocopy %AppData%\Local\CrashDumps %cdrive%%computername%\preserved-files\memory-dumps\ /ZB /copy:DAT /r:0 /ts /FP /np /E 

REM Garb NTUSER.DAT
mkdir %cdrive%%computername%\preserved-files\NTUSER_DAT
if %arch% == 32 (RawCopy.exe "%USERPROFILE%\NTUSER.DAT" %cdrive%%computername%\preserved-files\NTUSER_DAT) else (RawCopy64.exe "%USERPROFILE%\NTUSER.DAT" %cdrive%%computername%\preserved-files\NTUSER_DAT)

REM Copy UsrClass.dat
IF EXIST "C:\Users\" (
    for /D %%x in ("C:\Users\*") do (
	rawcopy.exe %%x\AppData\Local\Microsoft\Windows\UsrClass.dat %cdrive%%computername%\preserved-files\NTUSER_DAT
    )
)

REM Grab recent file cache
mkdir %cdrive%%computername%\preserved-files\AppCompat\
if %arch% == 32 (RawCopy.exe %WINDIR%\AppCompat\Programs\RecentFileCache.bcf %cdrive%%computername%\preserved-files\AppCompat) else (RawCopy64.exe %WINDIR%\AppCompat\Programs\RecentFileCache.bcf %cdrive%%computername%\preserved-files\AppCompat)
if %arch% == 32 (RawCopy.exe %SystemRoot%\AppCompat\Programs\Amcache.hve %cdrive%%computername%\preserved-files\AppCompat) else (RawCopy64.exe %SystemRoot%\AppCompat\Programs\Amcache.hve %cdrive%%computername%\preserved-files\AppCompat)

REM Grab NTFS artifacts
mkdir %cdrive%%computername%\preserved-files\ntfs\
if %arch% == 32 (RawCopy.exe %SYSTEMDRIVE%0 %cdrive%%computername%\preserved-files\ntfs) else (RawCopy64.exe %SYSTEMDRIVE%0 %cdrive%%computername%\preserved-files\ntfs)
if %arch% == 32 (RawCopy.exe %SYSTEMDRIVE%2 %cdrive%%computername%\preserved-files\ntfs) else (RawCopy64.exe %SYSTEMDRIVE%2 %cdrive%%computername%\preserved-files\ntfs)

REM copy start up data
mkdir %cdrive%%computername%\preserved-files\startup\
robocopy "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup" %cdrive%%computername%\preserved-files\startup\ /ZB /copy:DAT /r:0 /ts /FP /np /E 

REM SRUM collection
mkdir %cdrive%%computername%\srumdump\
if %arch% == 32 (RawCopy.exe %WINDIR%\System32\sru\SRUDB.dat %cdrive%%computername%\srumdump\ else (RawCopy64.exe %WINDIR%\System32\sru\SRUDB.dat %cdrive%%computername%\srumdump\)
srum_dump.exe -i %cdrive%%computername%\srumdump\SRUDB.dat -o %cdrive%%computername%\srumdump\%computername%.xlsx -t %cdrive%%computername%\srumdump\SRUM_TEMPLATE.xlsx

REM Grab memory image
mkdir %cdrive%%computername%\preserved-files\memory-image\
winpmem.exe %cdrive%%computername%\preserved-files\memory-image\physmem.raw -p

:: End - write out data and time
echo %DATE% %TIME% - Exiting collection script and stopping logging for computer %COMPUTERNAME% >> %cdrive%%computername%\Collection.log
:: create zip file of collected data
7za.exe a -tzip %computername%.zip a %cdrive%%computername%\
ENDLOCAL
:end
exit
