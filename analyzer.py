import logging
import logging.config
import configparser
import json
import sys
import time
from typing import TextIO
from dataclasses import dataclass

ANALYZER_CONFIG = 'analyzer.ini'



class Analyzer:
    # don't forget to use @property
    def __init__():
        ...

    def follow_log(file: TextIO) -> str:
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

    def store_record():
        ...
    
    def parse_record():
        ...
    
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

    # config = configparser.ConfigParser()
    # config.read(ANALYZER_CONFIG)
    
    # default_config = dict(config['DEFAULT'])
    # logging.debug(f"defualt config: {json.dumps(default_config)}")

    # try:
    #     logs_dir = default_config['auditd_logs_path']
    # except KeyError:
    #     logging.critical("the configuration is missing some defualt configurations")
    #     sys.exit(1)

    # with open(f"{logs_dir}/audit.log", "r") as audit_log:
    #     log_lines = follow(audit_log)
        
    #     for line in log_lines:
            
    #         entry = json.loads(line) # I will have to build my own parser
    #         logging.info(entry.dumps())
    #         logging.info(f"""{entry["event"]:10} {entry["eventTime"]:26} {entry["ownerUserId"]:6} {entry["path"]}""")