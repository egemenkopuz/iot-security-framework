from utilities.thread import FrameworkThread, ThreadInterface, Priority
from enum import Enum
from datetime import date
from enum import Enum, auto

import logging, queue, os, inspect, sys

class LogLevel(Enum):
    """
    Log level enums
    """
    DEBUG = '0'
    INFO = '1'
    WARNING = '2'
    ERROR = '3'
    CRITICAL = '4'

class Log():
    """
    Log blueprint
    """
    def __init__(self,message:str,level:LogLevel,frame=None):
        """
        Arguments:
        - message {str} -- string to be logged
        - level {LogLevel} -- LogLevel enum to differ logging
        
        Keyword Arguments:
        - frame {[FrameType]} -- information about the location of the code (default: {None})
        """
        self.message = message
        self.level = level 
        self.frame = frame

class LoggerInterface(ThreadInterface):
    def __init__(self, thread):
        super().__init__(thread)
    
    def write_log(self,msg:str,log_level:LogLevel,frame=None) -> None:
        log = Log(msg,log_level,frame)
        self._thread._channel.put(log)

class Logger(FrameworkThread):
    """
    Logging Management
    """
    def __init__(self,settings:dict,log_files_location:str,start:bool=False):
        """
        Arguments:
        - start {bool} -- forces thread to start after the initialization
        - settings {dict} -- general derived settings of the framework
        - logs_file_location {str} -- location of the log files
        """
        super().__init__('LOGGER', description='logger management', daemon=True, priority=Priority.LEVEL0)
        self._path = log_files_location
        
        # creates directory if there is none
        if not os.path.isdir(self._path):
            os.mkdir(self._path)

        # logging system initialization
        logging.basicConfig(filename='{}{}.log'.format(self._path,date.today().strftime("%d-%m-%Y")) , filemode='a', \
            format='[%(asctime)s.%(msecs)02d][%(levelname)s] %(message)s', datefmt='%d-%m-%y %H:%M:%S',level=settings['MIN_LOG_LEVEL'])

        # start is forced
        if start: self.start()

    def create_interface(self):
        self._interface = LoggerInterface(self)
        return self._interface


    def run(self):
        """
        Starts the thread, gets logs by the log queue and writes them to the log file
        """
        while not self._stop_request.is_set():
            try:
                log:Log = self._channel.get(True,0.05)
                if log.frame:
                    frame_info = inspect.getframeinfo(log.frame)
                    log.message = f'[{frame_info.filename},line:{frame_info.lineno}] {log.message}'
                if log.level == LogLevel.DEBUG:
                    logging.debug(log.message)
                elif log.level == LogLevel.INFO:
                    logging.info(log.message)
                elif log.level == LogLevel.WARNING:
                    logging.warning(log.message)
                elif log.level == LogLevel.ERROR:
                    logging.error(log.message)
                elif log.level == LogLevel.CRITICAL:
                    logging.critical(log.message)
            except queue.Empty:
                continue
            except:
                raise