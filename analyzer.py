import logging
import logging.config
import configparser
import json
import sys
import time
from typing import TextIO, Dict
from dataclasses import dataclass

ANALYZER_CONFIG = 'analyzer.ini'



class Analyzer:
    # don't forget to use @property
    def __init__(self):
        ...

    @property
    def current_file(self):
        """
        Returns the current file to read from. 
        If the analyzer reached the max lines go to the next file
        """
        return "/var/log/audit/audit.log"
    
    def run(self):
        """
        Go through the log files and stores the records into the database
        """
        with open(self.current_file, "r") as audit_log:
            records = self.follow_file(audit_log)
            
            for record in records:   
                logging.debug(self.parse_record(record))

    def follow_file(self, file: TextIO) -> str:
        """
        Reads the file and yield it's lines back to the caller 
        until reached the max lines for a log
        """
        l = 0
        while l < 10:
            line = file.readline()
            if not line:
                time.sleep(0.1)
                continue
            l += 1
            yield line

    def store_record(self, ):
        ...
    
    def parse_record(self, record_line: str) -> Dict:
        """
        Reads one record and return dictionary with field : value pairs.
        """
        return { pair.split('=')[0] : pair.split('=')[1] for pair in record_line.split(' ') }
    
    def save_state():
        # https://docs.python.org/3/library/atexit.html - atexit
        # https://docs.python.org/2/library/pickle.html#what-can-be-pickled-and-unpickled - save state
        ...

@dataclass
class AnalyzerState:
    ...
    # https://gist.github.com/tux-00/6093bfe1b5eef3049a7da493f312c77d
    def __post_init__(self):
        ...



if __name__ == "__main__":
    logging.basicConfig(format="%(levelname)s:%(asctime)s- %(message)s", level=logging.DEBUG)
    Analyzer().run()

    
         