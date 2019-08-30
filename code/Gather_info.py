import subprocess
from colorama import Fore, Back, Style
from data import *
import socket,os
from file import *

green = Fore.GREEN
reset = Fore.RESET
red = Fore.RED

class Gather():
    def systeminfo():
        ## run and print systeminfo results
        tools("psinfo.exe",psinfo)
        print(green+"\n\tLocal System Information: \n"+reset)
        sysinfo = subprocess.run("psinfo.exe -accepteula -s -h -d",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(sysinfo)
        
        ## Write results to file
        args = str(sysinfo)
        Files.mk_file("SYSTEM-INFO.txt",sysinfo)
        os.remove("psinfo.exe")
        return(sysinfo)
    
    def local_usersinfo():
        ## run and print UserInfo results
        print(green+"\n\tUsers Information: \n"+reset)        
        userInfo = subprocess.run("wmic useraccount get name,SID,Status\n",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(userInfo)
        
        ## run and print localAdmins results
        print(green + "\n\tLocal Users and Administrators: " + reset)     
        localAdmins = subprocess.run("powershell.exe Get-LocalGroupMember -Group Administrators\n",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(localAdmins)
        
        ## Write results to file
        args = ("{}{}".format(userInfo,localAdmins))
        Files.mk_file("USER-INFO.txt",args)
        
        return(userInfo,localAdmins)
    

        
    
class DeepBlue():    
    def deepBlue_security():
        tools("deepblue.ps1",deepblue)
        tools("regexes.txt",regexes)
        tools("whitelist.txt",whitelist)
        
        security  = subprocess.call("""powershell.exe ".\deepblue.ps1 -log security| Out-Host -Paging""",shell=True)
        
        os.remove("regexes.txt")
        os.remove("whitelist.txt")
        os.remove("deepblue.ps1")
        return(security)
    
    def deepBlue_system():
        tools("deepblue.ps1",deepblue)
        tools("regexes.txt",regexes)
        tools("whitelist.txt",whitelist)
        
        system = subprocess.call("""powershell.exe ".\deepblue.ps1 -log system | Out-Host -Paging""",shell=True)
        
        os.remove("regexes.txt")
        os.remove("whitelist.txt")
        os.remove("deepblue.ps1")    
        return(system)
    
    def deepBlue_powershell():
        tools("deepblue.ps1",deepblue)
        tools("regexes.txt",regexes)
        tools("whitelist.txt",whitelist)
        
        powershell = subprocess.call("""powershell.exe ".\deepblue.ps1 -log powershell | Out-Host -Paging""",shell=True)
        
        os.remove("regexes.txt")
        os.remove("whitelist.txt")
        os.remove("deepblue.ps1")
        
        return(powershell)
    

class Check():
    def startup_files():
        print(green+"\n\tChecking for startup programs:\n"+reset)
        dir_name = Files.name_file("")
        run = subprocess.call("""powershell.exe "Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-list " """,shell=True)
        startup = subprocess.run("""powershell.exe "Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-Table -Autosize | Out-String -Width 4096 " """,shell=False,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(run)
        
        args = "{}".format(startup)
        Files.mk_file("STARTUP_FILES.txt",args)
    
class Network_checks():
    def netstat_info():
        info = subprocess.run("""powershell.exe "netstat -ant | select -skip 4 | ConvertFrom-String -PropertyNames none, proto,ipsrc,ipdst,state,state2,none,none | select ipsrc,ipdst,state" """,shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(info)
        Files.mk_file("NETSTAT-INFO.txt",info)
        
        return(info)
    
    def netstat_listening():    
        print(green+"\n\tListening processes(brief):"+reset)
        listening_processes = subprocess.run("""powershell.exe "netstat -ano | findstr -i listening | ForEach-Object { $_ -split '\s+|\t+' } | findstr /r '^[1-9+]*$' | sort | unique | ForEach-Object { Get-Process -Id $_ } | Select ProcessName,Path,Company,Description | Format-Table -Autosize | Out-String -Width 4096" """,shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(listening_processes)
        
        net_info = subprocess.run("""powershell.exe "Get-NetTCPConnection -State Established|? RemoteAddress -NotLike '127.*'| Select RemoteAddress, RemotePort, OwningProcess, @{n='Path';e={(gps -Id $_.OwningProcess).Path}},@{n='Hash';e={(gps -Id $_.OwningProcess|gi|filehash).hash}}, @{n='User';e={(gps -Id $_.OwningProcess -IncludeUserName).UserName}}|sort|gu -AS|FT -Autosize | Out-String -Width 4096"  """,shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(green+"\n\n\tNetwork connections for running executable(Detailed):\n"+reset)
        print(net_info)
        args = "{}{}".format(listening_processes,net_info)
        Files.mk_file("NETSTAT-LISTENING_PROCESSES.txt",args)
        
        return(listening_processes,net_info)        
        
    def dns_checks():  
        dnsChecks = subprocess.run("""powershell.exe "Get-DnsClientCache -Status 'Success' | Select Name, Data" """,shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(dnsChecks)
        Files.mk_file("dnsChecks.txt",dnsChecks)
        return(dnsChecks)         

class System_files():
    def check_unsigned():
        print(green+"\n\tChecking for Unsigned executables on the system\n"+reset)
        unsigned = subprocess.run("""powershell.exe "Get-ChildItem -Recurse c:\*.exe -ea ig| ForEach-object {Get-AuthenticodeSignature $_ -ea ig} | Where-Object {$_.status -ine 'Valid'}|Select Status,Path |findstr 'NotSigned' """,shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(unsigned)
        
        Files.mk_file("UNSIGNED_EXEs.txt",unsigned)

    

class Memory():
    def mem_capture():
        tools("magnet.exe",magnet)
        name = "Investigations\{}\{}_Memory-Capture.raw".format(Files.name_file(""),socket.gethostname())
        print(name)
        
        print(green+"\n\tCapturing memory:\n"+reset)
        subprocess.call("""magnet.exe /accepteula /go "{}" """.format(name),shell=True)
        os.remove("magnet.exe")
