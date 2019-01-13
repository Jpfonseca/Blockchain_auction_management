import inspect
import logging
from logging import Logger
import sys


class LoggyLogglyMcface(Logger):

    def __init__(self, name, *args, **kwargs):
        """

        :param name:
        :param args:
        :param kwargs:
        """
        super().__init__(name, level=logging.NOTSET)
        self.logfile_handler=logging.StreamHandler(stream=sys.stdout)
        #self.logfile_handler=logging.FileHandler(filename="log.txt")
        self.logfile_handler.setLevel(logging.NOTSET)
        self.logfile_handler.setFormatter(logging.Formatter('%(asctime)15s -Class: {:10s} - %(levelname)15s - %(message)15s'.format(name)))
        self.addHandler(self.logfile_handler)
        self.manager.loggerDict[name] = self


if __name__ == '__main__':
    mylogger=LoggyLogglyMcface("Test")
    mylogger.log(level=logging.DEBUG,msg="TEst")

