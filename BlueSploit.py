import subprocess
from colorama import Fore, Back, Style

green = Fore.GREEN
reset = Fore.RESET

class Gather():
    def systeminfo():
        print(green+"\n\tLocal System Information: \n"+reset)
        sysinfo = subprocess.call("sysinternals\psinfo -accepteula -s -h -d",shell=True)
        return(sysinfo)
    
    def local_usersinfo():
        print(green+"\n\tUsers Information: \n"+reset)        
        userInfo = subprocess.call("wmic useraccount get name,SID,Status\n",shell=True)
        print(green + "\n\tLocal Users and Administrators: " + reset)
        localAdmins = subprocess.call("powershell.exe Get-LocalGroupMember -Group Administrators\n",shell=True)
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
        info = subprocess.call("""powershell.exe "netstat -ant | select -skip 4 | ConvertFrom-String -PropertyNames none, proto,ipsrc,ipdst,state,state2,none,none | select ipsrc,ipdst,state" """,shell=True)
        return(info)
    def netstat_listening():    
        listening_processes = subprocess.call("""powershell.exe "netstat -ano | findstr -i listening | ForEach-Object { $_ -split '\s+|\t+' } | findstr /r '^[1-9+]*$' | sort | unique | ForEach-Object { Get-Process -Id $_ } | Select ProcessName,Path,Company,Description" """,shell=True)
        return(listening_processes) 
    def dns_checks():  
        dnsChecks = subprocess.call("""powershell.exe "Get-DnsClientCache -Status 'Success' | Select Name, Data" """,shell=True)
        return(dnsChecks)
    
    
