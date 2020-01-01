import cmd2
from Gather_info import *
from data import *
from colorama import Fore, Back, Style
import cmd2_submenu
        

class Network_term(cmd2.Cmd):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = 'Network #> '
        self.hidden_commands.append('py')
        self.hidden_commands.append('set')
        self.hidden_commands.append('shortcuts')
        self.hidden_commands.append('macro')
        self.hidden_commands.append('alias')
        self.hidden_commands.append('run_script')
        self.hidden_commands.append('run_pyscript')
        self.hidden_commands.append('history')
        self.hidden_commands.append('shell')        
    
    Network = "Network data information and tasks"
    
    @cmd2.with_category(Network)
    def do_netstat_info(self,args):  
        Network.netstat_info()
        
    @cmd2.with_category(Network)
    def do_packet_capture(self,args):  
        """Live packet capture"""
        Network.packet_capture()    
    
    @cmd2.with_category(Network)
    def do_netstat_listening(self,args):  
        Network.netstat_listening()
    
    @cmd2.with_category(Network)
    def do_dns_cache(self,args):  
        Network.dns_checks()        


class Query_term(cmd2.Cmd):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = 'Query_WinEvents #> '
        self.hidden_commands.append('py')
        self.hidden_commands.append('set')
        self.hidden_commands.append('shortcuts')
        self.hidden_commands.append('macro')
        self.hidden_commands.append('alias')
        self.hidden_commands.append('run_script')
        self.hidden_commands.append('run_pyscript')
        self.hidden_commands.append('history')
        self.hidden_commands.append('shell')        
   
    Query_WinEvents = "Query Windows events"
    
    @cmd2.with_category(Query_WinEvents)
    def do_check_security(self,args):
        """Check for suspicious security windows events"""
        DeepBlue.deepBlue_security()
        
    @cmd2.with_category(Query_WinEvents)
    def do_check_system(self,args):
        """Check for suspicious system windows events"""
        DeepBlue.deepBlue_system()        

    @cmd2.with_category(Query_WinEvents)
    def do_check_powershell(self,args):
        """Check for suspicious powershell windows events"""
        DeepBlue.deepBlue_powershell() 
        
        
        



class System_Info_term(cmd2.Cmd):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = 'System_Info #> '
        hidecomands(self)
      

    system_information = "View system information"
    
      
    @cmd2.with_category(system_information)
    def do_gather_sysinfo(self,args):
        """Gather system information"""
        Gather.systeminfo()
          
         

    @cmd2.with_category(system_information)
    def do_gather_usersinfo(self,args):
        """Gather local user information"""
        Gather.local_usersinfo()
            
    
        
class Inspect_term(cmd2.Cmd):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = 'Inspect #> '
        hidecomands(self)

    inspect_system = "Inspecting system for malicious artifacts on executables/processes/files/services"
    
    @cmd2.with_category(inspect_system)    
    def do_inspect_exe_unsigned(self,args):
        """Inspecting system for unsigned executables"""
        Inspect.inspect_unsigned()
        
    @cmd2.with_category(inspect_system)    
    def do_inspect_strings(self,args):
        """Inspecting suspicious lines of chosen executable"""
        Inspect.inspect_exe_strings()        
    
    @cmd2.with_category(inspect_system)
    def do_inspect_startup(self,args):
        """Inspect registry startup files and their locations"""
        Inspect.inspect_startup()   
        
    @cmd2.with_category(inspect_system)
    def do_inspect_processes(self,args):
        """Inspect running processes"""
        Inspect.inspect_processes()       
        
    @cmd2.with_category(inspect_system)
    def do_inspect_loggedOnUsers(self,args):
        """Inspect Logged On Users"""
        Inspect.inspect_loggedonusers()     
        
        
class Yara_term(cmd2.Cmd):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = 'yara #> '
        hidecomands(self)

    yara_search = "Looking into a specific directory(ies) for a match against the yara rules of your choise"
    
    
    @cmd2.with_category(yara_search)
    def do_yara_search(self,args):
        """Yara search"""
        Yara.yara_check()       
             
        
class Mem_term(cmd2.Cmd):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = 'Memory #> '
        hidecomands(self)

    mem_tasks = "Memory Acquisition tasks"
    
    @cmd2.with_category(mem_tasks)
    def do_memory_capture(self,args):
        """Capture system's raw memory"""
        Memory.mem_capture()          


class Remediation_term(cmd2.Cmd):   
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = 'Remediation #> '
        hidecomands(self)
        

    remediation = "Remediate of threats found"
    
    @cmd2.with_category(remediation)
    def do_remediate_domain(self,args):
        """Remediation of malicious domain"""
        Remediation.block_domain()    
    
    @cmd2.with_category(remediation)
    def do_remediate_ip(self,args):
        """Remediation of malicious IP"""
        Remediation.block_ip()   

class Remote_term(cmd2.Cmd):   
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = 'houseKeeping #> '
        hidecomands(self)
    
    housekeeping = "House Keeping commands to execute in the end of the investigation"
            
    @cmd2.with_category(housekeeping)
    def do_zip_investigation(self,args):
        """Zipping investigation folder"""
        Remote.zipfiles()
        
        
    def do_copy2remote(self,args):
        """Coppying and zipying investigation file to remote host"""
        Remote.zipfiles()
        Remote.copyfiles()
        
    
    def do_cleanup(self,args):
        """Deleting investigation and files"""
        Remote.cleanup()     
    
class Hash_term(cmd2.Cmd):   
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = 'Hash #> '
        hidecomands(self)
        
    hash_file = "Choose any files to hash"

    @cmd2.with_category(hash_file)    
    def do_hash_file(self,args):
        """Hash any file"""
        Gather.hash_files()  
        
    @cmd2.with_category(hash_file)    
    def do_hash_directory(self,args):
        """Hash all files inside a directory (sha256)"""
        Gather.hash_directory()      
        
class IOC_term(cmd2.Cmd):   
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = 'IOCs #> '
        hidecomands(self)
        
    _ioc = "Extract/defang IOCs"

    @cmd2.with_category(_ioc)    
    def do_extract_IOCs(self,args):
        """Extract and defang IOCs from files"""
        IOC.extract_iocs() 
        
    @cmd2.with_category(_ioc)    
    def do_defang_IOCs(self,args):
        """Defang typed IOC"""
        IOC.defang_iocs()
       
class Collect_term(cmd2.Cmd):   
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = 'collect #> '
        hidecomands(self)
        
    _collect = "Collect file system artifacts"

    @cmd2.with_category(_collect)
    def do_collect_win_logs(self,args):
        """Collect Security|System|Powershell event logs"""
        Collect.collect_evtx() 
        
    @cmd2.with_category(_collect)
    def do_collect_prefetch(self,args):
        """Collect prefetch files from system"""
        Collect.copy_prefetch()          
    
    @cmd2.with_category(_collect)
    def do_create_timeline(self,args):
        """Collect data from multiple sources to form the timeline of events"""
        Collect.create_timeline()    
    
    @cmd2.with_category(_collect)
    def do_collect_shellbags(self,args):
        """Collect ShellBags from the specified user"""
        Collect.collect_shellbags()    
        
    @cmd2.with_category(_collect)
    def do_collect_browsinghistory(self,args):
        """Collect browsing history for all users"""
        Collect.browsingHistory() 
        
    @cmd2.with_category(_collect)
    def do_collect_file(self,args):
        """Collect suspicious files (copying the file into the "investigations" folder"""
        Collect.copy_file()      
    
        
@cmd2_submenu.AddSubmenu(Collect_term(),
                         command='collect')        
@cmd2_submenu.AddSubmenu(IOC_term(),
                         command='IOC')
@cmd2_submenu.AddSubmenu(Remote_term(),
                         command='housekeeping')
@cmd2_submenu.AddSubmenu(Remediation_term(),
                         command='remediate')
@cmd2_submenu.AddSubmenu(Mem_term(),
                         command='memory')    
@cmd2_submenu.AddSubmenu(Inspect_term(),
                         command='inspect')
@cmd2_submenu.AddSubmenu(Network_term(),
                         command='network')
@cmd2_submenu.AddSubmenu(Query_term(),
                         command='query_win_events')
@cmd2_submenu.AddSubmenu(System_Info_term(),
                         command='sysinfo')
@cmd2_submenu.AddSubmenu(Yara_term(),
                         command='yara')
@cmd2_submenu.AddSubmenu(Hash_term(),
                         command='hash')
class BlueSploit(cmd2.Cmd):
    intro = cmd2.style(""" \n ______  _               _____         _         _  _   
| ___ \| |             /  ___|       | |       (_)| |  
| |_/ /| | _   _   ___ \ `--.  _ __  | |  ___   _ | |_ 
| ___ \| || | | | / _ \ `--. \| '_ \ | | / _ \ | || __|
| |_/ /| || |_| ||  __//\__/ /| |_) || || (_) || || |_ 
\____/ |_| \__,_| \___|\____/ | .__/ |_| \___/ |_| \__|
                              | |                      
                              |_|                      

  """,bold=True,fg="blue")
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = (Style.RESET_ALL + Style.BRIGHT  + Back.BLUE + "\nBlueSploit $> "+ Style.RESET_ALL +  Fore.GREEN)    
        hidecomands(self)

        
    listmod = "List all available modules"    
    @cmd2.with_category(listmod)    
    def do_list_modules(self,args):
        print("\n")
        modules()


if __name__ == '__main__':
    app = BlueSploit()
    app.cmdloop()