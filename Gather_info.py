import subprocess
from colorama import Fore, Back, Style
from data import *

green = Fore.GREEN
reset = Fore.RESET

class Gather():
    def systeminfo():
        ## run and print systeminfo results
        print(green+"\n\tLocal System Information: \n"+reset)
        sysinfo = subprocess.run("sysinternals\psinfo -accepteula -s -h -d",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(sysinfo)
        
        ## Write results to file
        args = str(sysinfo)
        Files.mk_file("system-info.txt",sysinfo)
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
        security  = subprocess.call("""powershell.exe "DeepBlueCLI\DeepBlue.ps1 -log security| Out-Host -Paging""",shell=True)
        return(security)
    def deepBlue_system():
        system = subprocess.call("""powershell.exe "DeepBlueCLI\DeepBlue.ps1 -log security | Out-Host -Paging""",shell=True)
        return(system)
    def deepBlue_powershell():
        powershell = subprocess.call("""powershell.exe "DeepBlueCLI\DeepBlue.ps1 -log powershell | Out-Host -Paging""",shell=True)
        return(powershell)
    
    
class Network_checks():
    def netstat_info():
        info = subprocess.run("""powershell.exe "netstat -ant | select -skip 4 | ConvertFrom-String -PropertyNames none, proto,ipsrc,ipdst,state,state2,none,none | select ipsrc,ipdst,state" """,shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(info)
        Files.mk_file("netstat-info.txt",info)
        
        return(info)
    
    def netstat_listening():    
        print(green+"\n\tListening processes(brief):"+reset)
        listening_processes = subprocess.run("""powershell.exe "netstat -ano | findstr -i listening | ForEach-Object { $_ -split '\s+|\t+' } | findstr /r '^[1-9+]*$' | sort | unique | ForEach-Object { Get-Process -Id $_ } | Select ProcessName,Path,Company,Description" """,shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(listening_processes)
        
        net_info = subprocess.run("""powershell.exe "Get-NetTCPConnection -State Established|? RemoteAddress -NotLike '127.*'| Select RemoteAddress, RemotePort, OwningProcess, @{n='Path';e={(gps -Id $_.OwningProcess).Path}},@{n='Hash';e={(gps -Id $_.OwningProcess|gi|filehash).hash}}, @{n='User';e={(gps -Id $_.OwningProcess -IncludeUserName).UserName}}|sort|gu -AS|FT" """,shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(green+"\n\n\tNetwork connections for running executable(Detailed):\n"+reset)
        print(net_info)
        args = "{}{}".format(listening_processes,net_info)
        Files.mk_file("netstat-listening_processes.txt",args)
        
        return(listening_processes,net_info)        
        
    def dns_checks():  
        dnsChecks = subprocess.run("""powershell.exe "Get-DnsClientCache -Status 'Success' | Select Name, Data" """,shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(dnsChecks)
        Files.mk_file("dnsChecks.txt",dnsChecks)
        return(dnsChecks)         
            
    
