import inspect
from logging import *
from logging import Logger
import sys


class LoggyLogglyMcface(Logger):
    """
    This class specifies a Logger adapted to our needs.
    It will print the logs based on the level of the warning/error and will be associated with a message from the class
    which called it.
    """
    def __init__(self, name,level=DEBUG,output=None, *args, **kwargs):
        """

        :param name: name of the class which calls the logger
        :param level: level of warnings/errors to show in the log. The levels to be used should be NOTSET, DEBUG, ERROR.
        Each of them prints less info than the previous ones
        :param output: This parameter specifies the place to which the logs will be printed. There are 2 options available :
            "std"  ->prints to standart output
            "other"->log file
        :param args: extra arguments
        :param kwargs:extra arguments
        """

        super().__init__(name, level=level)
        if output== "std":
            self.logfile_handler=StreamHandler(stream=sys.stdout)
        else:
            self.logfile_handler=FileHandler(filename="log.txt")
        self.logfile_handler.setLevel(level)
        self.logfile_handler.setFormatter(Formatter('%(asctime)15s -Class: {:10s} - %(levelname)15s - %(message)15s'.format(name)))
        self.addHandler(self.logfile_handler)
        self.manager.loggerDict[name] = self


if __name__ == '__main__':
    mylogger=LoggyLogglyMcface("Test")
    mylogger.log(level=DEBUG,msg="TEst")

