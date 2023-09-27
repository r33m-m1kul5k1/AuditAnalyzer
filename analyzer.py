import logging
import logging.config
import configparser
import time
import sys
import sqlite3
import re
import pickle
from base64 import b64decode, b64encode
import atexit
from typing import TextIO, Dict
from dataclasses import dataclass, field

ANALYZER_CONFIG = 'analyzer.ini'



class Analyzer:
    
    def __init__(self, config):
        self.database_conn = sqlite3.connect(config.database_path)
        self.cursor = self.database_conn.cursor()
        
        self.cursor.execute('CREATE TABLE IF NOT EXISTS misc_records(type TEXT, misc_fields TEXT)')
        self.cursor.execute('CREATE TABLE IF NOT EXISTS commands(exe TEXT, grouped_records TEXT)')
        self.cursor.execute('CREATE TABLE IF NOT EXISTS rules(key TEXT, grouped_records TEXT)')
        
    @property
    def current_file(self):
        """
        Returns the current file to read from. 
        If the analyzer reached the max lines go to the next file
        """
        return '/var/log/audit/audit.log'
    
    def run(self):
        """
        Go through the log files and stores the records into the database
        """
        with open(self.current_file, 'r') as audit_log:
            records = self.follow_file(audit_log)
            
            for record in records: 
                record = self.parse_record(record)
                if record:
                    self.store_record(record)

    def follow_file(self, file: TextIO) -> str:
        """
        Reads the file and yield it's lines back to the caller 
        until reached the max lines for a log
        """
        l = 0
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.1)
                continue
            l += 1
            yield line

    def store_record(self, record: Dict):
        """
        stores records, and group all commands and rules together
        """
        if 'exe' in record:
            command_info = {k:record[k] for k in record if k != 'exe' };
           
            grouped_records = self.cursor.execute(
                'SELECT grouped_records FROM commands WHERE exe = ?',
                (record['exe'],)
                ).fetchone()
            
            if not grouped_records:
                print(command_info)
                self.cursor.execute(
                    'INSERT INTO commands (exe, grouped_records) VALUES (?, ?)',
                    (record['exe'], b64encode(pickle.dumps([command_info])).decode())
                    )
            else:
                grouped_records = pickle.loads(b64decode(grouped_records[0]))
                grouped_records.append(command_info)
                self.cursor.execute(
                    'UPDATE commands SET grouped_records = ?',
                        (b64encode(pickle.dumps(grouped_records)),)
                    )

        if 'key' in record:
            ...
        
        if 'exe' not in record and 'key' not in record:
            logging.debug(f'inserting a misc record => {record}')
            self.cursor.execute(
                'INSERT INTO misc_records VALUES (?, ?)',
                (
                    record['type'],
                    b64encode(pickle.dumps({k:record[k] for k in record if k != 'type' }), )
                    ))
            
        self.database_conn.commit()
    
    def parse_record(self, record_line: str) -> Dict | None:
        """
        Reads one record and return dictionary with field : value pairs.
        """
        try:
            return { pair.split('=')[0] : pair.split('=')[1] for pair in record_line.split(' ') } 
        except:
            logging.error(f'invalid record => {record_line}')

    def save_state(self):
        # https://docs.python.org/3/library/atexit.html - atexit
        # https://docs.python.org/2/library/pickle.html#what-can-be-pickled-and-unpickled - save state
        self.database_conn.close()
        logging.debug('saved analyzer state')

@dataclass
class AnalyzerState:
    ...
    # https://gist.github.com/tux-00/6093bfe1b5eef3049a7da493f312c77d
    

@dataclass 
class Config:
    """ This class holds all the configurations to the project"""
    path: str 
    auditd_logs_path: str = field(init=False)
    # audit log file maximum size in megabytes
    max_log_file: int = field(init=False)
    database_path: str = field(init=False)


    def __post_init__(self):
        config = configparser.ConfigParser()
        config.read(self.path)

        try:
            self.auditd_logs_path = config['DEFAULT']['auditd_logs_path']
            self.max_log_file = config['DEFAULT']['max_log_file']
            self.database_path = config['DEFAULT']['database_path']
        except KeyError:
            logging.critical('the configuration is missing some defualt configurations')
            sys.exit(1)
        
if __name__ == "__main__":
    
    logging.basicConfig(format='%(levelname)s:%(asctime)s- %(message)s', level=logging.DEBUG)
    analyzer = Analyzer(Config(ANALYZER_CONFIG))
    atexit.register(analyzer.save_state)
    analyzer.run()
    

    
         