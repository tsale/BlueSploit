import cmd2
from Gather_info import *
from colorama import Fore, Back, Style, init
import cmd2_submenu


class Gather_term(cmd2.Cmd):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.prompt = 'Gather $> '

    gather_information = "Gather Information"

    @cmd2.with_category(gather_information)
    def do_gather_sysinfo(self,args):
        """Gather system information"""
        Gather.systeminfo()

    @cmd2.with_category(gather_information)
    def do_gather_local_usersinfo(self,args):
        """Gather local user information"""
        Gather.local_usersinfo()
    
    @cmd2.with_category(gather_information)
    def do_check_deep_security(self,args):
        Gather.deepBlue_security()
        
    def do_check_deep_system(self,args):
        Gather.deepBlue_system()        

    def do_check_deep_powershell_snippet(self,args):
        Gather.deepBlue_powershell_snippet()    

@cmd2_submenu.AddSubmenu(Gather_term(),
                         command='gather',
                 aliases=('g',))
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

    def do_deepBlue(self, args):
        self.poutput(cmd2.style('Deep Blue test', fg='green'))





if __name__ == '__main__':
    app = BlueSploit()
    app.cmdloop()
