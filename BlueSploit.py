import cmd2
from Gather_info import *
from data import *
from colorama import Fore, Back, Style, init
import cmd2_submenu

class Query_term(cmd2.Cmd):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = 'Query #> '

    
    Query_WinEvents = "Query Windows events"


    @cmd2.with_category(Query_WinEvents)
    def do_check_deep_security(self,args):
        Gather.deepBlue_security()
        
    @cmd2.with_category(Query_WinEvents)
    def do_check_deep_system(self,args):
        Gather.deepBlue_system()        

    @cmd2.with_category(Query_WinEvents)
    def do_check_deep_powershell_snippet(self,args):
        Gather.deepBlue_powershell_snippet() 



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
    def do_gather_local_usersinfo(self,args):
        """Gather local user information"""
        Gather.local_usersinfo()
    


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
