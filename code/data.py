import csv
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
    mods = {'sysInfo':'Gather Information',
            'network':'Show current network information',
            'memory':'Memory forensics',
            'inspect':'Inspect system for malicious artifacts',
            'yara':'Use Yara to search for malicious artifacts',
            'remediate':'Remediate of threats found' ,           
            'query_win_events':'Query Windows events',
            'houseKeeping':'House Keeping commands'}            
    
    for k,v in mods.items():
        print(f"\t{k} =>\t\t{v}")


           
class Files():
    def name_file(name):
        timestr = time.strftime("%m-%d-%Y-")
        filename = socket.gethostname()
        inv_name = "Bluesploit_{time}{filename}_{module_name}".format(time=timestr,filename=filename,module_name=name)
        return(inv_name)
    
    def mk_file(name,*args):
        filename = Files.name_file(name)
        f = open("Investigations/{}/{}".format(Files.name_file(""),filename), "w",newline='')   
        f.write(*args)
        f.close()
        

        

os.makedirs("Investigations/{}".format(Files.name_file("")),exist_ok=True)
os.makedirs("Investigations/yara-rules",exist_ok=True)
subprocess.call("powershell.exe $ErrorActionPreference= 'silentlycontinue'",shell=True)