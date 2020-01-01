import time
import socket
import os
import subprocess



def hidecomands(self):
    self.hidden_commands.append('py')
    self.hidden_commands.append('set')
    self.hidden_commands.append('shortcuts')
    self.hidden_commands.append('macro')
    self.hidden_commands.append('alias')
    self.hidden_commands.append('run_script')
    self.hidden_commands.append('run_pyscript')
    self.hidden_commands.append('history')
    self.hidden_commands.append('shell')     

def modules():
    mods = {'sysinfo':'View system info',
            'network':'Show current network information',
            'memory':'Memory forensics',
            'inspect':'Inspect system for malicious artifacts',
            'remediate':'Remediate of threats found' ,           
            'houseKeeping':'House Keeping commands',
            'IOC':'Extract and defang IOCs',
            'query_win_events':'Query Windows events',
            'collect':'Collect file system artifacts',
            'yara':'Use Yara to search for malicious artifacts'}            
    
    for k,v in mods.items():
        print(f"\t{k} =>\t\t{v}")


           
class Files():
    def name_file(name):
        timestr = time.strftime("%m-%d-%Y-")
        filename = socket.gethostname()
        inv_name = f"Bluesploit_{timestr}{filename}_{name}"
        return(inv_name)
    
    def mk_file(name,*args):
        try:
            filename = Files.name_file(name)
            f = open(f"Investigations/{Files.name_file('')}/{filename}", "w",newline='')   
            f.write(*args)
            f.close()
        except Exception as e:
            print(e)
            
        

        

os.makedirs(f"Investigations/{Files.name_file('')}",exist_ok=True)
os.makedirs("Investigations/yara-rules",exist_ok=True)
subprocess.call("powershell.exe $ErrorActionPreference= 'silentlycontinue'",shell=True)