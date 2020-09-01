from utilities.thread import FrameworkThread,ThreadInterface,ThreadMessage, Priority

import queue, threading, copy, time

class Threads:
    """
    Utility class to hold threads based on their priority levels along with 
    their corresponding mutexes which will are to be used for modifications
    """
    def __init__(self):
        self.level0_threads = {}
        self.level1_threads = {}
        self.level2_threads = {}
        self.mm0 = threading.Lock()
        self.mm1 = threading.Lock()
        self.mm2 = threading.Lock()

class Archive(FrameworkThread):
    """
    Archive Thread for thread management by handling all threads in the system, 
    provide inspection and limited accessibility to these threads
    """
    def __init__(self):
        super().__init__(name='ARCHIVE', description='thread management', daemon=False, priority=Priority.LEVEL0)
        self._threads = Threads()

    def __remove_inactive_threads(self) -> None:
        """
        Removes inactive threads
        """
        self._threads.mm0.acquire()
        self._threads.level0_threads = {key:value for key, value in self._threads.level0_threads.items() if value.isAlive()}
        self._threads.mm0.release()

        self._threads.mm1.acquire()
        self._threads.level1_threads = {key:value for key, value in self._threads.level1_threads.items() if value.isAlive()}
        self._threads.mm1.release()

        self._threads.mm2.acquire()
        self._threads.level2_threads = {key:value for key, value in self._threads.level2_threads.items() if value.isAlive()}
        self._threads.mm2.release()

    def terminate_all(self) -> None:
            """
            Terminates the all framework threads in specific order.
            Threads which are daemons will not be affected 
            Termination Order: 2 -> 1 -> 0
            """

            # gets all accesses beforehand
            self._threads.mm2.acquire()
            self._threads.mm1.acquire()
            self._threads.mm0.acquire()

            # terminates elective threads
            for thread_id, thread in self._threads.level2_threads.items():
                if not thread.isDaemon(): 
                    thread.terminate(wait=False)
            for thread_id, thread in self._threads.level2_threads.items():
                if not thread.isDaemon(): 
                    thread.join()

            # terminates critical threads
            for thread_id, thread in self._threads.level1_threads.items():
                if not thread.isDaemon(): 
                    thread.terminate(wait=False)
            for thread_id, thread in self._threads.level1_threads.items():
                if not thread.isDaemon(): 
                    thread.join()

            # terminates core threads
            for thread_id, thread in self._threads.level0_threads.items():
                if not thread.isDaemon(): 
                    thread.terminate(wait=False)
            for thread_id, thread in self._threads.level0_threads.items():
                if not thread.isDaemon(): 
                    thread.join()

            self._threads.mm2.release()
            self._threads.mm1.release()
            self._threads.mm0.release()
            
    def get_all(self) -> dict:
        """
        Get all threads
        """
        return {**self._threads.level0_threads, **self._threads.level1_threads,**self._threads.level2_threads}

    def get_threads(self,level:int) -> dict:
        """
        Get threads with given specific level

        Arguments:
        - level (int) : level of the thread(s)
        """
        if level == 0: return self._threads.level0_threads
        elif level == 1: return self._threads.level1_threads
        elif level == 2: return self._threads.level2_threads
        else: raise ValueError(level)

    def create_interface(self):
        self._interface = ArchiveInterface(self)
        return self._interface

    def run(self):
        """
        Check threads every second if there is any dead threads
        """
        while not self._stop_request.is_set():
            try:
                self.__remove_inactive_threads()
                time.sleep(0.05)   # sleep for 0.05 second
            except Exception as e:
                print(e)
                self._stop_request.set()

class ArchiveInterface(ThreadInterface):
    """
    Interface for Archive
    """
    def __init__(self, archive:Archive):
        super().__init__(archive)


    def get_thread(self,thread_id:int) -> ThreadInterface:
        """
        Get thread with given thread id
        """
        return {**self._threads.level0_threads, **self._threads.level1_threads,**self._threads.level2_threads}[thread_id]

    def get_all_threads(self) -> dict:
        """
        Get all threads in the system
        """
        return self._thread.get_all()

    def get_level0_threads(self) -> dict:
        """
        Get level 0 threads (essential)
        """
        return self._thread.get_threads(0)

    def get_level1_threads(self) -> dict:
        """
        Get level 1 threads (IoT Devices)
        """
        return self._thread.get_threads(1)
    
    def get_level2_threads(self) -> dict:
        """
        Get level 2 threads (Companion App)
        """
        return self._thread.get_threads(2)

    def add_thread(self,thread:FrameworkThread) -> bool:
        """
        Add a newly created thread to the system for further inspection and visibility

        Arguments:
        - thread (FrameworkThread) : 
        """
        if thread.is_alive():
            if thread.priority == Priority.LEVEL0:
                self._thread._threads.mm0.acquire()
                self._thread._threads.level0_threads[thread.ident] = thread
                self._thread._threads.mm0.release()
            elif thread.priority == Priority.LEVEL1:
                self._thread._threads.mm1.acquire()
                self._thread._threads.level1_threads[thread.ident] = thread
                self._thread._threads.mm1.release()
            elif thread.priority == Priority.LEVEL2:
                self._thread._threads.mm2.acquire()
                self._thread._threads.level2_threads[thread.ident] = thread
                self._thread._threads.mm2.release()
            return True
        else:
            return False

    def add_threads(self,*args):
        """
        Add thread(s) to the system
        """
        for thread in args:
            if thread.is_alive():
                if thread.priority == Priority.LEVEL0:
                    self._thread._threads.mm0.acquire()
                    self._thread._threads.level0_threads[thread.ident] = thread
                    self._thread._threads.mm0.release()
                elif thread.priority == Priority.LEVEL1:
                    self._thread._threads.mm1.acquire()
                    self._thread._threads.level1_threads[thread.ident] = thread
                    self._thread._threads.mm1.release()
                elif thread.priority == Priority.LEVEL2:
                    self._thread._threads.mm2.acquire()
                    self._thread._threads.level2_threads[thread.ident] = thread
                    self._thread._threads.mm2.release()

        

        


    