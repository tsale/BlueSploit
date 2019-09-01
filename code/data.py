import csv
import time
import socket
import os
import subprocess


def modules():
    mods = {'gather':'Gather Information',
            'query':'Query Windows events',
            'network':'Show current network information',
            'memory':'Memory forensics',
            'inspect':'Inspect system for malicious artifacts'}
    
    for k,v in mods.items():
        print("{}\t=>\t\t{}".format(k,v))



def write_csv():
    nlist = []
    ninput = input("Add your note:\n")
    #ninput = ("{}\n".format(ninput))
    nlist.append(ninput)
    with open('notes.csv', 'a',newline='') as csvFile:
        for x in nlist:
            writer = csv.writer(csvFile)
            writer.writerow([x])
            csvFile.close()


def show_notes():
    with open('notes.csv', 'r') as csvFile:
        reader = csv.reader(csvFile)
        for row in reader:
            print(row)
            
            
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
subprocess.call("powershell.exe $ErrorActionPreference= 'silentlycontinue'",shell=True)