import logging
import logging.config
import configparser
import time
import sys
import sqlite3
import re
import pickle
import os
import json
import atexit
from typing import TextIO, Dict
from dataclasses import dataclass, field

ANALYZER_CONFIG = 'analyzer.ini'

def load_analyzer_state(path: str):
    """
    Loads the analyzer state from the pickled file or creates a new state
    """
    try:
        with open(path, 'rb') as file:
            state = pickle.load(file)
    except FileNotFoundError:
        logging.info('creating a new state object')
        state = AnalyzerState()
    return state


class Analyzer:
    
    def __init__(self, config):
        self.config = config
        self.state = load_analyzer_state(config.analyzer_state_path)
        self.database_conn = sqlite3.connect(config.database_path)
        self.cursor = self.database_conn.cursor()
        
        self.cursor.execute('CREATE TABLE IF NOT EXISTS misc_records(type TEXT, misc_fields TEXT)')
        self.cursor.execute('CREATE TABLE IF NOT EXISTS commands(exe TEXT, grouped_records TEXT)')
        self.cursor.execute('CREATE TABLE IF NOT EXISTS rules(key TEXT, grouped_records TEXT)')

    @property
    def current_file(self) -> str:
        """
        Returns the current file path to read from. 
        If the analyzer reached the max lines go to the next file
        """
        log_files = os.listdir(self.config.auditd_logs_path)
        return f"{self.config.auditd_logs_path}/{log_files[self.state.current_file_index]}"
          
    def run(self):
        """
        Go through the log files and stores the records into the database
        """
        
        logging.debug(f"current state = {self.state}")
        while True:
            records = self.follow_file()
            
            for record in records: 
                record = self.parse_record(record)
                if record:
                    self.store_record(record)
            
            self.state.current_file_index = (self.state.current_file_index + 1) % self.config.num_logs
            logging.debug(f'moving to {self.current_file}')
    

    def follow_file(self) -> str:
        """
        Reads the file and yield it's lines back to the caller 
        until reached the max lines for a log
        """
        with open(self.current_file, 'r') as file:
            file.seek(self.state.current_byte)

            while self.state.current_byte < self.config.max_log_file * 2**20:
                line = file.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                yield line
                self.state.current_byte = file.tell()
         
            
    def store_record(self, record: Dict):
        """
        stores records, and group all commands and rules together
        """

        if 'exe' in record:
            rule_info = {k:record[k] for k in record if k != 'exe' };
           
            grouped_records = self.cursor.execute(
                'SELECT grouped_records FROM commands WHERE exe = ?',
                (record['exe'],)
                ).fetchone()
            
            if not grouped_records:
                self.cursor.execute(
                    'INSERT INTO commands (exe, grouped_records) VALUES (?, ?)',
                    (record['exe'], json.dumps([rule_info]))
                    )
            else:
                grouped_records = json.loads(grouped_records[0])
                grouped_records.append(rule_info)
                self.cursor.execute(
                    'UPDATE commands SET grouped_records = ?',
                        (json.dumps(grouped_records),)
                    )

        if 'key' in record and record['key'] != '(nil)':
            rule_info = {k:record[k] for k in record if k != 'key' };
           
            grouped_records = self.cursor.execute(
                'SELECT grouped_records FROM rules WHERE key = ?',
                (record['key'],)
                ).fetchone()
            
            if not grouped_records:
                self.cursor.execute(
                    'INSERT INTO rules (key, grouped_records) VALUES (?, ?)',
                    (record['key'], json.dumps([rule_info]))
                    )
            else:
                grouped_records = json.loads(grouped_records[0])
                grouped_records.append(rule_info)
                self.cursor.execute(
                    'UPDATE rules SET grouped_records = ?',
                        (json.dumps(grouped_records),)
                    )
        
        if 'exe' not in record and 'key' not in record:
            
            self.cursor.execute(
                'INSERT INTO misc_records VALUES (?, ?)',
                (
                    record['type'],
                    json.dumps({k:record[k] for k in record if k != 'type' }, )
                    ))
            
        self.database_conn.commit()
    

    def parse_record(self, record_line: str) -> Dict | None:
        """
        Reads one record and return dictionary with field : value pairs.
        """
        record_line = f' {record_line} '
        try:
            return dict(zip(re.findall(' (.*?)=', record_line), re.findall('=(.*?) ', record_line)))
        except:
            logging.error(f'invalid record => {record_line}')

    def save_state(self):
        """
        Pickles the analyzer state into a temp file and close the database connection
        """
        with open(self.config.analyzer_state_path, 'wb') as file:
            pickle.dump(self.state, file)
        self.database_conn.close()
        logging.debug('saved analyzer state')

@dataclass
class AnalyzerState:
    current_byte: int = 0
    current_file_index: int = 0

    

@dataclass 
class Config:
    """ This class holds all the configurations to the project"""
    path: str 
    auditd_logs_path: str = field(init=False)
    # audit log file maximum size in megabytes
    max_log_file: int = field(init=False)
    database_path: str = field(init=False)
    analyzer_state_path: str = field(init=False)
    # audit maximum number of log files
    num_logs: int = field(init=False)


    def __post_init__(self):
        config = configparser.ConfigParser()
        config.read(self.path)

        try:
            self.auditd_logs_path = config['DEFAULT']['auditd_logs_path']
            self.max_log_file = int(config['DEFAULT']['max_log_file'])
            self.database_path = config['DEFAULT']['database_path']
            self.analyzer_state_path = config['DEFAULT']['analyzer_state_path']
            self.num_logs = int(config['DEFAULT']['num_logs'])
        except KeyError:
            logging.critical('the configuration is missing some defualt configurations')
            sys.exit(1)
        
if __name__ == "__main__":
    
    logging.basicConfig(format='%(levelname)s:%(asctime)s- %(message)s', level=logging.DEBUG)
    analyzer = Analyzer(Config(ANALYZER_CONFIG))
    atexit.register(analyzer.save_state)
    analyzer.run()
    

    
         