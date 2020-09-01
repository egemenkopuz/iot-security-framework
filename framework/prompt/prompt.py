from utilities.thread import FrameworkThread, ThreadInterface, Priority

from enum import Enum, auto

import cmd, threading, queue


class CommandType(Enum):
    """
    Command type enums
    """
    EXIT = auto()
    THREADS = auto()

class Command:
    """
    Command blueprint
    """
    def __init__(self,command_type:CommandType,content=None):
        """
        Arguments:
        - command_type {CommandType} : type of the command
        - content : content to be delivered inside the command (default: {None})
        """
        self.command_type = command_type
        self.content = content

class Shell(cmd.Cmd):
    """
    Command parser and processor (shell)
    """

    # prompt message before the input (can cause visual problems if there are other outputs in the shell)
    prompt = '' # optional: 'shell> '
    
    # introduction message for the shell
    intro = "   _____                              ______            __             __   \n" + \
            "  / ___/___  _______  __________     / ____/___  ____  / /__________  / /   \n" + \
            "  \__ \/ _ \/ ___/ / / / ___/ _ \   / /   / __ \/ __ \/ __/ ___/ __ \/ /    \n" + \
            " ___/ /  __/ /__/ /_/ / /  /  __/  / /___/ /_/ / / / / /_/ /  / /_/ / /     \n" + \
            "/_________/\___/\__,_/_/   \___/   \____/\____/_/ /_/\____/   \____/_/      \n" + \
            "   / ____/________ _____ ___  ___ _      ______  _____/ /__                 \n" + \
            "  / /_  / ___/ __ `/ __ `__ \/ _ \ | /| / / __ \/ ___/ //_/                 \n" + \
            " / __/ / /  / /_/ / / / / / /  __/ |/ |/ / /_/ / /  / ,<                    \n" + \
            "/_/   /_/   \__,_/_/ /_/ /_/\___/|__/|__/\____/_/  /_/|_|  ver 1.0 alpha    \n" + \
            f"\n>>> Type help or ? to list all the commands\n"

    def __init__(self,settings:dict,queue:queue.Queue,signal):
        """
        Arguments:
        - settings {dict} -- general derived settings of the framework
        - queue {queue.Queue} -- parsed commands are put into this queue for further processing
        - signal {Event} -- thread's stop request flag
        """
        super().__init__(self)
        self.use_rawinput = False
        self.signal = signal
        self.settings = settings
        self.queue = queue
    
    def default(self,line):
        """
        If invalid command is received, stops further parsing and prints error message
        """
        print(f"error> {line} is not a valid command. See 'help' or '?'")

    def emptyline(self):
        """
        If empty input is receieved, stops further parsing
        """
        return False

    def precmd(self, line):
        return line

    def postcmd(self, stop, line):
        """
        After the command is parsed, checks if stop request signal is raised from the thread
        and lock is closed to get further command
        """
        if self.signal.isSet(): 
            return True
        return None

    def do_exit(self,input):
        """
        Command func for 'exit' input from the user
        """
        self.queue.put(Command(CommandType.EXIT))
        self.signal.set()
    
    def do_threads(self,input):
        """
        Command func for 'threads' input from the user
        """
        self.queue.put(Command(CommandType.THREADS))

    def do_help(self,input):
        """
        Command func for 'help' or '?' input from the user
        """
        print('\n>>> Commands:\n\n'
              ' exit                    Terminate all threads and close the program\n'
              ' threads                 Show all active threads in the framework\n'
              ' show <target>           Show all the active users and IoT devices in the network (target: all, users, iots)\n'
              ' disconnect <target>     Disconnect a specific active client or Iot device\n')


class Prompt(FrameworkThread):
    def __init__(self,settings:dict):
        super().__init__('PROMPT', 'command management', daemon=True, priority=Priority.LEVEL0)        
        
        # initilization of shell
        self._shell = Shell(settings,self._channel,self._stop_request)

    def create_interface(self):
        self._interface = PromptInterface(self)
        return self._interface

    def run(self):
        """
        Start the thread, gets command inputs from the user via prompt
        """
        self._shell.cmdloop()

class PromptInterface(ThreadInterface):
    def __init__(self, thread):
        super().__init__(thread)

    def get_command(self,blocked:bool=True,time=0.1) -> Command:
        return self._thread._channel.get(blocked,time)