import cmd2
from Gather_info import *
from data import *
from colorama import Fore, Back, Style
import cmd2_submenu



class Network_term(cmd2.Cmd):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = 'Network #> '
    
    Network = "Network data information"
    
    @cmd2.with_category(Network)
    def do_netstat_info(self,args):  
        Network_checks.netstat_info()
    
    @cmd2.with_category(Network)
    def do_netstat_listening(self,args):  
        Network_checks.netstat_listening()
    
    @cmd2.with_category(Network)
    def do_dns_checks(self,args):  
        Network_checks.dns_checks()        


class Note_term(cmd2.Cmd):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = 'notes #> '

    Notes = "Keep notes"


    @cmd2.with_category(Notes)
    def do_add_note(self,args):
        """Add a note"""
        write_csv()
      
    @cmd2.with_category(Notes)
    def do_show_notes(self,args):
        """show all the notes"""
        show_notes()
    

class Query_term(cmd2.Cmd):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = 'Query #> '
   
    Query_WinEvents = "Query Windows events"
    
    @cmd2.with_category(Query_WinEvents)
    def do_check_deep_security(self,args):
        """Check for suspicious security windows events"""
        DeepBlue.deepBlue_security()
        
    @cmd2.with_category(Query_WinEvents)
    def do_check_deep_system(self,args):
        """Check for suspicious system windows events"""
        DeepBlue.deepBlue_system()        

    @cmd2.with_category(Query_WinEvents)
    def do_check_deep_powershell(self,args):
        """Check for suspicious powershell windows events"""
        DeepBlue.deepBlue_powershell() 
        
        
        



class Gather_term(cmd2.Cmd):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = 'Gather #> '

    gather_information = "Gather Information"
    
      

    @cmd2.with_category(gather_information)
    def do_gather_sysinfo(self,args):
        """Gather system information"""
        Gather.systeminfo()
          
         

    @cmd2.with_category(gather_information)
    def do_gather_usersinfo(self,args):
        """Gather local user information"""
        Gather.local_usersinfo()
        
        
        
class Inspect_term(cmd2.Cmd):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = 'Inspect #> '

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
    def do_check_startup_files(self,args):
        """Check registry startup files and their locations"""
        Inspect.inspect_startup()        
        
             
        
class Mem_term(cmd2.Cmd):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = 'Memory #> '

    mem_tasks = "Memory Acquisition tasks"
    
    @cmd2.with_category(mem_tasks)
    def do_memory_capture(self,args):
        """Capture system's raw memory"""
        Memory.mem_capture()          

@cmd2_submenu.AddSubmenu(Mem_term(),
                         command='memory')    
@cmd2_submenu.AddSubmenu(Inspect_term(),
                         command='inspect')
@cmd2_submenu.AddSubmenu(Network_term(),
                         command='network')
@cmd2_submenu.AddSubmenu(Note_term(),
                         command='notes')
@cmd2_submenu.AddSubmenu(Query_term(),
                         command='query')
@cmd2_submenu.AddSubmenu(Gather_term(),
                         command='gather')
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


    def do_list_modules(self,args):
        modules()
    

if __name__ == '__main__':
    app = BlueSploit()
    app.cmdloop()
