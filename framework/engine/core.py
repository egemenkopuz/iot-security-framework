from utilities.thread import FrameworkThread, ThreadInterface, ThreadMessage
from utilities.exceptions import FrameworkInitilizationError
from utilities.logger import Logger, LoggerInterface, LogLevel
from prompt.prompt import Prompt, PromptInterface, Command, CommandType
from database.database import Database, DatabaseInterface
from engine.archive import Archive, ArchiveInterface
from network.server import Server, ServerInterface

import yaml, sys, queue

CERTIFICATES_FILE_LOCATION = sys.path[0] + '/certificates/'
SETTINGS_FILE_LOCATION = sys.path[0] + '/settings.yaml'
DATABASE_FILE_LOCATION = sys.path[0] + '/database.sqlite3'
LOG_FILES_LOCATION = sys.path[0] + '/logs/'

class Core:
    def __init__(self):
        try:
            # --------------------------------------------------------------------------------- #
            # General settings of the framework is held in the form of dictionary               #
            # --------------------------------------------------------------------------------- #

            self._settings = self.__load_settings(SETTINGS_FILE_LOCATION)       # GENERAL FRAMEWORK SETTINGS

            # --------------------------------------------------------------------------------- #
            # There are 5 main threaded components of this framework and all threads            #
            # have their own custom interfaces for limited external access                      #
            # --------------------------------------------------------------------------------- #

            # (LOGGER) is responsible for getting logs out of other threads asynchronously so 
            # that other threads do not have to waste time writing logs to a file

            self._logger = Logger(self._settings,LOG_FILES_LOCATION)            # LOGGER THREAD
            self._logger_interface = self._logger.create_interface()            # LOGGER INTERFACE

            # (ARCHIVE) is responsible for maintenance of threads by removing inactive threads from the system

            self._archive = Archive()                                           # ARCHIVE THREAD
            self._archive_interface = self._archive.create_interface()          # ARCHIVE INTERFACE

            # (DATABASE) is responsible for ensurance of data in the tables and the whole connection to the database

            self._database = Database(self._settings,DATABASE_FILE_LOCATION)    # DATABASE THREAD
            self._database_interface = self._database.create_interface()        # DATABASE INTERFACE
            
            # (PROMPT) is responsible for parsing and deliverance of commands given by the admin-user via command shell

            self._prompt = Prompt(self._settings)                               # PROMPT THREAD
            self._prompt_interface = self._prompt.create_interface()            # PROMPT INTERFACE

            # (SERVER) is rensponsible for accepting clients and assigning them accordingly to the system

            self._server = Server(self._settings,CERTIFICATES_FILE_LOCATION)    # SERVER THREAD
            self._server_interface = self._server.create_interface()            # SERVER INTERFACE

            # --------------------------------------------------------------------------------- #
            # Establishing intercommunication by assigning corresponding interfaces             #
            # --------------------------------------------------------------------------------- #

            # adding logger's interface to other main threads
            self._archive.add_access_to_logger(self._logger_interface)
            self._database.add_access_to_logger(self._logger_interface)
            self._prompt.add_access_to_logger(self._logger_interface)
            self._server.add_access_to_logger(self._logger_interface)

            # adding archive's interface to other main threads
            self._database.add_access_to_archive(self._archive_interface)
            self._logger.add_access_to_archive(self._archive_interface)
            self._database.add_access_to_archive(self._archive_interface)
            self._prompt.add_access_to_archive(self._archive_interface)
            self._server.add_access_to_archive(self._archive_interface)

            # adding database's interface to other main threads
            self._prompt.add_access_to_database(self._database_interface)
            self._server.add_access_to_database(self._database_interface)

        except Exception as e:
            raise FrameworkInitilizationError(e)

    def start(self):
        """
        Starts all the main threads and processes commands sent by prompt
        """

        # all level 0 threads started their processes
        self._logger.start()
        self._archive.start()
        self._database.start()
        self._prompt.start()
        self._server.start()

        # all threads are added to the archive's thread system
        self._archive_interface.add_threads(self._logger,self._archive,self._database,self._prompt,self._server)
        
        # main framework loop
        while True:
            try:
                # gets parsed command from prompt system 
                cmd = self._prompt_interface.get_command()
                if cmd.command_type == CommandType.EXIT: break

            except queue.Empty:
                continue
            except Exception as e:
                self._logger_interface.write_log(e,LogLevel.CRITICAL)
                break

        self._archive.terminate_all()

    def __load_settings(self,path:str) -> dict:
        """
        Loads settings from a yaml file

        Arguments:
        - path {str} : path of the yaml file
        """
        with open(path,'r') as f:
            return yaml.load(f,Loader=yaml.FullLoader)