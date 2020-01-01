from colorama import Fore
from data import *
from file import *
from scapy.all import sniff
from scapy.all import wrpcap
from datetime import date
import subprocess
import socket,os
import re
import pydoc
import time
import shutil
import hashlib
import iocextract
import csv


green = Fore.GREEN
yellow = Fore.YELLOW
reset = Fore.RESET
red = Fore.RED
curdir = os.getcwd()
hostname = socket.gethostname()
ntv_folder = Files.name_file("")
final_path = curdir + "\\Investigations\\" + ntv_folder
yara_path = f"{curdir}\\Investigations\\yara-rules"
today = date.today().strftime("%d-%m-%Y")




class Gather():
    def hash_files():
        file_path = input("Insert the complete file path of the file to hash: ")
        
        BUF_SIZE = 65536  # lets read stuff in 64kb chunks!
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                md5.update(data)
                sha1.update(data)
                sha256.update(data)
        
        hashed_fl = f"\nFile: {green}{file_path}\nMD5: {md5.hexdigest()}\nSHA1: {sha1.hexdigest()}\nSHA256: {sha256.hexdigest()}\n"       
        print(hashed_fl)
        
        Files.mk_file("hashed_files.txt",hashed_fl)
        
    
    def hash_directory():
        file_path = input("Directory of files to hash: ")
        dir_name = os.path.basename(file_path)
        mydict = {}
        for root, dirs,files in os.walk(file_path, topdown=True):
            for name in files:
                FileName = (os.path.join(root, name))
        
                hasher = hashlib.sha256()
                with open(str(FileName), 'rb') as afile:
                    buf = afile.read()
                    hasher.update(buf)
                mydict[name]=hasher.hexdigest()
        print(f"\nHashed files(Sha256) for directory '{dir_name}': \n")        
        for file,_hash in mydict.items():
            print(f"{green}{file}{reset}{red} => {reset}{_hash}")
        
        with open(f'{final_path}\\{dir_name}-hashed_files.csv', 'w',newline="") as csvfile: 
            writer = csv.writer(csvfile) 
            writer.writerow(['FileName', 'Sha256'])    
            for key, value in mydict.items():
                writer.writerow([key, value])        
    
    
    
    def systeminfo():
        ## run and print systeminfo results
        tools("psinfo.exe",psinfo)
        print(green+"\n\tLocal System Information: \n"+reset)
        sysinfo = subprocess.run("psinfo.exe -accepteula -s -h -d",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(sysinfo)
        
        ## Write results to file
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
        localAdmins = subprocess.run("net localgroup administrators\n",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(localAdmins)
        
        ## Write results to file
        args = (f"{userInfo}{localAdmins}")
        Files.mk_file("USER-INFO.txt",args)
        
        return(userInfo,localAdmins)
    
        
    
class DeepBlue():    
    def deepBlue_security():
        tools("deepblue.ps1",deepblue)
        tools("regexes.txt",regexes)
        tools("whitelist.txt",whitelist)
        
        security  = subprocess.run("""powershell.exe ".\deepblue.ps1 -log security |Format-Table -Autosize | Out-String -Width 4096""",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        
        os.remove("regexes.txt")
        os.remove("whitelist.txt")
        os.remove("deepblue.ps1")
        
        pydoc.pager(security)
        Files.mk_file("Security_Deep.txt",security)           
    
    def deepBlue_system():
        tools("deepblue.ps1",deepblue)
        tools("regexes.txt",regexes)
        tools("whitelist.txt",whitelist)
        
        system = subprocess.run("""powershell.exe ".\deepblue.ps1 -log system |Format-Table -Autosize | Out-String -Width 4096""",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        
        os.remove("regexes.txt")
        os.remove("whitelist.txt")
        os.remove("deepblue.ps1")   
        
        pydoc.pager(system)
        Files.mk_file("System_deep.txt",system)        
        
    
    def deepBlue_powershell():
        tools("deepblue.ps1",deepblue)
        tools("regexes.txt",regexes)
        tools("whitelist.txt",whitelist)
        
        powershell = subprocess.run("""powershell.exe ".\deepblue.ps1 -log powershell |Format-Table -Autosize | Out-String -Width 4096""",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        
        os.remove("regexes.txt")
        os.remove("whitelist.txt")
        os.remove("deepblue.ps1")
        
        print(powershell)
        Files.mk_file("Powershell_Deep.txt",powershell)
        
        return(powershell)
    
    
class Network():
    
    def netstat_info():
        info = subprocess.run("""powershell.exe "netstat -ant | select -skip 4 | ConvertFrom-String -PropertyNames none, proto,ipsrc,ipdst,state,state2,none,none | select ipsrc,ipdst,state" """,shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(info)
        Files.mk_file("NETSTAT-INFO.txt",info)
        
        return(info)
    
    def netstat_listening():    
        print(green+"\n\tListening processes(brief):"+reset)
        listening_processes = subprocess.run("""powershell.exe "netstat -ano | findstr -i listening | ForEach-Object { $_ -split '\s+|\t+' } | findstr /r '^[1-9+]*$' | sort | unique | ForEach-Object { Get-Process -Id $_ } | Select ProcessName,Path,Company,Description | Format-Table -Autosize | Out-String -Width 4096 | ConvertTo-CSV -Delimiter "`t" -NoTypeInformation | % { $_ -replace "`"" } | Set-Content netstat.csv" """,shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(listening_processes)
        
        net_info = subprocess.run("""powershell.exe "Get-NetTCPConnection -State Established|? RemoteAddress -NotLike '127.*'| Select RemoteAddress, RemotePort, OwningProcess, @{n='Path';e={(gps -Id $_.OwningProcess).Path}},@{n='Hash';e={(gps -Id $_.OwningProcess|gi|filehash).hash}}, @{n='User';e={(gps -Id $_.OwningProcess -IncludeUserName).UserName}}|sort|gu -AS|FT -Autosize | Out-String -Width 4096"  """,shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(green+"\n\n\tNetwork connections for running executable(Detailed):\n"+reset)
        print(net_info)
        args = f"{listening_processes}{net_info}"
        Files.mk_file("NETSTAT-LISTENING_PROCESSES.txt",args)
        
        return(listening_processes,net_info)        
        
    def dns_checks():  
        dnsChecks = subprocess.run("""powershell.exe "Get-DnsClientCache -Status 'Success' | Select Name, Data" """,shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(dnsChecks)
        Files.mk_file("dnsChecks.txt",dnsChecks)
        return(dnsChecks)         
    
    def packet_capture():
        show_int = subprocess.run("netsh interface show interface",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        interface = input(f"Choose from below interfaces:\n {show_int} (Case sensitive) -->  ")
        
        while True:
            try:
                run_time = int(input("Choose how long you would like the capture to run for (in minutes): "))
                break
            except:
                print("Please insert an integer number\n")
        
      

            
        try:
            print(green+f"\nCreating PCAP under: {final_path}\\{hostname}.pcap\n\nCheck back in {run_time} minutes from now.\nExecution time:({time.ctime()})\n"+reset)
            run_time = run_time *60   
            pakts_list = sniff(timeout=run_time,iface=interface)
            wrpcap(f'{final_path}\\{hostname}.pcap',pakts_list)                         

        except:
            ans_np = input("Npcap is not installed, do you want to install it?(y/n): ")
            if "y" in ans_np.lower():
                tools("npcap.exe",npcap)
                subprocess.call("npcap.exe",shell=True)
                os.remove("npcap.exe")
                print("\n RESTART BlueSploit in order for this to work.\n")
            elif "n" in ans_np.lower():
                pass
            else:
                print("Please answer with y or n")
            
   

class Inspect():
    
    def inspect_startup():
        print(green+"\n\tChecking for startup programs:\n"+reset)
        run = subprocess.call("""powershell.exe "Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-list " """,shell=True)
        startup = subprocess.run("""powershell.exe "Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-Table -Autosize | Out-String -Width 4096 " """,shell=False,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(run)
        
        args = f"{startup}"
        Files.mk_file("STARTUP_FILES.txt",args)    
    
    def inspect_unsigned():
        print(green+"\n\tChecking for Unsigned executables on the system\n"+reset)
        unsigned1 = subprocess.run("""powershell.exe "Get-ChildItem -Recurse c:\\windows\\*.exe -ea ig| ForEach-object {Get-AuthenticodeSignature $_ -ea ig} | Where-Object {$_.status -ine 'Valid'}|Select Status,Path |findstr 'NotSigned'" """,shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        unsigned2 = subprocess.run("""powershell.exe "Get-ChildItem -Recurse c:\\users\\*.exe -ea ig| ForEach-object {Get-AuthenticodeSignature $_ -ea ig} | Where-Object {$_.status -ine 'Valid'}|Select Status,Path |findstr 'NotSigned'" """,shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        
        print(unsigned1)
        print(unsigned2)
        
        os.mkdir(f"{final_path}\\Unsigned_EXEs")

        Files.mk_file("UNSIGNED_EXEs_WindowsDir.txt",unsigned1)
        Files.mk_file("UNSIGNED_EXE_UsersDir.txt",unsigned2)
        
        shutil.move(f"{final_path}\\{Files.name_file('')}UNSIGNED_EXEs_WindowsDir.txt",f"{final_path}\\Unsigned_EXEs\\Unsigned_EXEs_WindowsDir.txt")
        shutil.move(f"{final_path}\\{Files.name_file('')}UNSIGNED_EXE_UsersDir.txt",f"{final_path}\\Unsigned_EXEs\\Unsigned_EXEs_UsersDir.txt")


            
    
    def inspect_exe_strings():
        tools("strings.exe",strings)
        strings_exe = input(green+"Insert executable including its path: (e.g. C:\malicious.exe ): ")
        strings_cmd = subprocess.check_output(f"""strings.exe -n 10 "{strings_exe}" """.decode('utf-8'))
        strings_cmd = strings_cmd.replace("\n", " ")
        strings_cmd = strings_cmd.replace("\r", " ")          
        
        
        ips = re.findall('[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*',strings_cmd)
        ips = (f"\nLooking for IPs from {strings_exe}\n{ips}\n") 
        print(ips)
        time.sleep(2)

        
        urls = re.findall('http[s]?:\/\/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',strings_cmd)
        urls = (f"\nLooking for URLs from {strings_exe}\n{urls}\n\n") 
        print(urls)
        time.sleep(2)
        
        unicode = subprocess.check_output(f"""strings.exe -nobanner -n 5 -u {strings_exe}" """.decode('utf-8'))
        unicode = (f"\nLooking for UNICODE from {strings_exe}\n\n{unicode}") 
        print(unicode)
        
        
        args = f"{ips}{urls}{unicode}"
        strings_exe = strings_exe.rsplit("\\",1)[-1]
        Files.mk_file(f"STRINGS-{strings_exe}.txt",args)
        
        os.remove("strings.exe")
        
    def inspect_processes():
        tools("pslist.exe",pslist)
        plist = subprocess.run(f"pslist.exe -accepteula -t -nobanner",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(plist)
        
        Files.mk_file("running-processes.txt",plist) 
        os.remove("pslist.exe")
        
    def inspect_loggedonusers():
        query = subprocess.run(f"query user",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(query)
        Files.mk_file("LoggedOnUsers.txt",query) 

        
class Yara():
    def yara_check():
        tools("yara.exe",yara)
        print(f"Please move the yara rules under {yara_path}")
        rule_name = input("Enter the name(s) of yara rules to run: ")
        rule_match_path = input("Enter the directory you want to search against: ") 
        
        yara_cmd = subprocess.run(f"yara.exe -r -s --no-warnings -f {yara_path}\\{rule_name} {rule_match_path}  2> nul ",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(f"\n{yara_cmd}")
        
        if yara_cmd:
            Files.mk_file("Yara_matches.txt",yara_cmd)
            print("\nWe have a match!")
        else:
            print("No matches found!")

class Memory():
    def mem_capture():
        tools("magnet.exe",magnet)
        name = f"{final_path}_Memory-Capture.raw"
        print(name)
        
        print(green+"\n\tCapturing memory:\n"+reset)
        subprocess.call(f"""magnet.exe /accepteula /go "{name}" """,shell=True)
        os.remove("magnet.exe")
        
        
class Remediation():
    def block_domain():
        domain = input("Enter domain (no asterisk allowed) to block: ")
        subprocess.call(f"""powershell.exe "Add-Content C:\Windows\System32\drivers\etc\hosts "`n127.0.0.1 {domain}" """,shell=True)
        print(f"\n{domain} domain is now blocked")
        
    def block_ip():
        ip = input("Enter IP to block: ")
        subprocess.call("""powershell.exe "New-NetFirewallRule -DisplayName "Block_Malicious_IP" -Direction Outbound -LocalPort Any -Protocol TCP -Action Block -RemoteAddress {}" """.format(ip),shell=True)
        print(f"\n{ip} ip is now blocked")
    

class Remote():
    def zipfiles():
        filename = f"Investigation-{socket.gethostname()}"
        shutil.make_archive(f"{filename}_{today}", 'zip', f'{os.getcwd()}\\Investigations') 
        print(f"{green}[*] Investigations folder has been zipped succesfully{reset}\n")
        
        
    def copyfiles():
        filename = f"{os.getcwd()}\\Investigation-{socket.gethostname()}.zip".replace('C:\\','C$')
        print(f"{green}\\\\ Run the following command to transfer the file to your workstation after you exit psexec session:\nCommand => copy \\\\{socket.gethostname()}\\{filename} C$\ {reset}")
        
    def cleanup():
        filename = f"Investigation-{socket.gethostname()}_{today}.zip"
        try:
            os.remove(f"{filename}")
        except:
            pass
        shutil.rmtree("Investigations")
        
        
class IOC():
    def extract_iocs():
        file = input("File you want to extract IOCs from(full file path): ")
        iocs = []
        with open(file, "r") as f:
            f = f.read()
            print(f"{green}\nIOCs extracted:\n{reset}")
            for everything in iocextract.extract_iocs(f):
                iocs.append(iocextract.defang(everything))
                print(f"{red}{iocextract.defang(everything)}{reset}")
        iocs = "\n".join(iocs)
        Files.mk_file("extract_iocs.txt",iocs)
        
    def defang_iocs():
        ioc = input("URL or IP you want to defang: ")
        print(f"\n{yellow}{iocextract.defang(ioc)}{reset}")
        
      
class Collect:
    def collect_evtx():
        print(green+f"\n\t Copying Security|System|Powershell events to:\n ==> {final_path}\\evtx_logs: \n"+reset)   
        try:
            os.makedirs(f"{final_path}\\evtx_logs")
        except:
            pass
        fin_path = f"{final_path}\\evtx_logs"
        
        
        subprocess.run(f"wevtutil epl Security {fin_path}\Security.evtx\n",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        subprocess.run(f"wevtutil epl System {fin_path}\System.evtx\n",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        subprocess.run(f"wevtutil epl Microsoft-Windows-PowerShell/Operational {fin_path}\Microsoft-Windows-PowerShel_Operational.evtx\n",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')    
     
   
    def copy_prefetch():
        tools("WinPrefetchView.exe",WinPrefetchView)
        print(green+f"\n\t Collecting prefetching files to\n ==> {final_path}\\prefetch.html: \n"+reset)   
    
        subprocess.run(f"""WinPrefetchView.exe /sort "~Modified Time" /sverhtml {final_path}\prefetch.html""",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        os.remove("WinPrefetchView.exe")
        
    
    def create_timeline():
        tools("LastActivityView.exe",LastActivityView)
        print(green+f"\n\t Creating timeline of events files to\n ==> {final_path}\\timeline\\timeline.(html/csv): \n"+reset)   
        
        os.mkdir(f"{final_path}\\timeline")
        subprocess.run(f"LastActivityView.exe /sverhtml {final_path}\\timeline\\timeline.html",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        subprocess.run(f"LastActivityView.exe /scomma {final_path}\\timeline\\timeline.csv",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        
        os.remove("LastActivityView.exe")    
        
        
    def collect_shellbags():
        tools("CBECmd.exe",CBECmd)
        user = input("Please enter the user name: ")
        
        print(green+f"\n\t Collecting ShellBags. Saving csv to directory\n ==> {final_path}\ShellBags: \n"+reset)   
        
        subprocess.run(f"""CBECmd.exe --csv {final_path}\\ShellBags -d C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Windows --tz "Pacific Standard Time" """,shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        
        os.remove("CBECmd.exe")    
        
        
    def browsingHistory():
        tools("BrowsingHistoryView.exe",BrowsingHistoryView)
        days = input("How many days worth of history would you like to collect?: ")
        
        print(green+f"\n\t Collecting browsing history. Saving csv to\n ==> {final_path}\BrowsingHistory.csv: \n"+reset)   
        
        subprocess.run(f"""BrowsingHistoryView.exe /HistorySource 1 /VisitTimeFilterType 3 /VisitTimeFilterValue {days} /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 0 /sort ~2 /scomma {final_path}\\BrowsingHistory.csv""",shell=True,stdout=subprocess.PIPE).stdout.decode('utf-8')
        
        os.remove("BrowsingHistoryView.exe")            
        
    
    def copy_file():
        file = input("Type the file you want to copy(full file path): ")
        _final_path = final_path + "\\collected_files"
        try:
            os.mkdir(f"{final_path}\\collected_files")
        except:
            pass
        shutil.copy2(file, _final_path)      #shutil.copy2 will attempts to preserve all the source file's metadata