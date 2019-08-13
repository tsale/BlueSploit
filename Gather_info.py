import subprocess
from colorama import Fore, Back, Style

green = Fore.GREEN
reset = Fore.RESET

class Gather():
    def systeminfo():
        print(green+"\n\tLocal System Information: \n"+reset)
        subprocess.call("sysinternals\psinfo -accepteula -s -h -d",shell=True)

    def local_usersinfo():
        print(green+"\n\tUsers Information: \n"+reset)        
        subprocess.call("wmic useraccount get name,SID,Status\n",shell=True)
        print(green + "\n\tLocal Users and Administrators: " + reset)
        subprocess.call("powershell.exe Get-LocalGroupMember -Group Administrators\n",shell=True)
        
    def deepBlue_security():
        subprocess.call("powershell.exe DeepBlueCLI\DeepBlue.ps1 -log security",shell=True)
    
    def deepBlue_system():
        subprocess.call("""powershell.exe "DeepBlueCLI\DeepBlue.ps1 -log security | Out-Host -Paging""",shell=True)
    
    def deepBlue_powershell_snippet():
        subprocess.call("""powershell.exe "DeepBlueCLI\DeepBlue.ps1 -log powershell | Out-Host -Paging""",shell=True)      


