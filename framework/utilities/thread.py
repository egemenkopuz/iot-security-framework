from enum import Enum

import threading, queue

class Priority(Enum):
    LEVEL0 = '0'
    LEVEL1 = '1'
    LEVEL2 = '2'

class ThreadMessageType(Enum):
    CONNECTION_BEGIN = b'00'
    CONNECTION_END = b'99'
    TRANSFER = b'10'

class ThreadMessage:
    def __init__(self,sender_tid:int,message_type:ThreadMessageType,data=None):
        self.sender_tid = sender_tid
        self.message_type = message_type
        self.data = data

class FrameworkThread(threading.Thread):
    """
    Framework Thread Blueprint
    """
    def __init__(self,name:str,description:str,daemon:bool,priority:Priority):
        super().__init__(name=name,daemon=daemon)
        self.priority = priority
        self.description = description

        self._stop_request = threading.Event()
        self._channel = queue.Queue()

        self._interface = None
        self._archive_interface = None
        self._logger_interface = None
        self._database_interface = None

    def create_interface(self):
        self._interface = ThreadInterface(self)
        return self._interface

    def add_access_to_archive(self,archive_interface):
        self._archive_interface = archive_interface

    def add_access_to_logger(self,logger_interface):
        self._logger_interface = logger_interface

    def add_access_to_database(self,database_interface):
        self._database_interface = database_interface

    def terminate(self,wait:bool=True,timeout:int=None) -> None:
        """
        Ends the thread's lifetime by enabling thread's stop request event 

        Keyword Arguments:
        - wait {bool} -- if should wait for thread to finish itself (default: {True})
        - timeout {int} -- how long is the wait (default: {None})
        """
        self._stop_request.set()
        if wait: super().join(timeout)

class ThreadInterface:
    """
    Framework Thread Interface which provides 1-way communication
    """
    def __init__(self,thread:FrameworkThread):
        self._thread = thread

    def is_alive(self) -> bool:
        return self._thread.isAlive()

    def details(self) -> (int,str,str):
        return self._thread.ident,self._thread.name,self._thread.description
        
    def send(self,message:ThreadMessage,block:bool=False,timeout:int=None) -> bool:
        """
        Sends a message to the thread
        
        Arguments:
        - message {ThreadMessage} -- Message to be sent
        
        Keyword Arguments:
        - block {bool} -- whether to wait until gate is empty (default: {False})
        - timeout {int} -- how long is the wait if blocked (default: {None})
        
        Returns:
        - bool -- indicates the success
        """
        try:
            if not self.is_alive(): return False
            self._thread._channel.put(message,block=block,timeout=timeout)
            return True
        except:
            return False




