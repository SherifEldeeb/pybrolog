''' Bro IDS logs library '''

from datetime import datetime
from re import match

class BroLogBase():
    ''' Base class for Bro IDS logs'''
    log_file = ''
    empty_field = ''
    fields = []
    fields_types = []
    parameters_dict = {}
    path = ''
    separator = ''
    set_separator = ''
    types = []
    unset_field = ''
    datetime_to_isoformat = False

    def __init__(self, log_file, datetime_to_isoformat=False):
        self.datetime_to_isoformat = datetime_to_isoformat
        self.log_file = open(log_file, 'r')
        self.parameters_dict = self.__get_parameters()
        for key in self.parameters_dict:
            setattr(self, key, self.parameters_dict[key])
    def __get_parameters(self):
        ''' Get parameters of the logfile, returns a dict'''
        parameters_dict = {}
        log = self.log_file
        # First line '[0] #separator \x09' ... delimeted by SPACE
        parameters_dict['separator'] = log.readline().strip().split(' ')[1].replace('\\', '0')
        parameters_dict['separator'] = chr(int(parameters_dict['separator'], 16))
        # Subsequent lines are delimeted by (parameters_dict['separator'])
        sep = parameters_dict['separator']
        # '[1] #set_separator	,'
        parameters_dict['set_separator'] = log.readline().strip().split(sep)[1]
        # '[2] #empty_field	(empty)'
        parameters_dict['empty_field'] = log.readline().strip().split(sep)[1]
        # '[3] #unset_field	-'
        parameters_dict['unset_field'] = log.readline().strip().split(sep)[1]
        # '[4] #path	capture_loss' ... that's the type of log file!! <---
        parameters_dict['path'] = log.readline().strip().split(sep)[1]
        # '[5] #open	2016-11-24-22-01-30'
        parameters_dict['open'] = log.readline().strip().split(sep)[1]
        # Fields and Types sould be lists
        # '[6] #fields	ts	ts_delta	peer	gaps	acks	percent_lost'
        parameters_dict['fields'] = log.readline().strip()
        parameters_dict['fields'] = parameters_dict['fields'].split(sep)
        del parameters_dict['fields'][0]
        # '[7] #types	time	interval	string	count	count	double'
        parameters_dict['types'] = log.readline().strip()
        parameters_dict['types'] = parameters_dict['types'].split(sep)
        del parameters_dict['types'][0]
        # And a convenient dict to zip fields with types
        parameters_dict['fields_types'] = dict(zip(parameters_dict['fields'],
                                                   parameters_dict['types']))
        return parameters_dict

class BroLog(BroLogBase):
    ''' Class for Bro IDS logs, iterable'''
    def __iter__(self):
        return self

    def __next__(self):
        ''' Get next log entry, returns a dict'''
        entry = self.log_file.readline()
        if entry == '':
            raise StopIteration
        if entry[0] == '#': # last line in logs is something like '#close	2016-11-25-00-21-46'
            return None
        else:
            entry = entry.strip().split(self.parameters_dict['separator'])
            for index, value in enumerate(entry):
                if '[' in self.types[index]: # is the type a list of values,e.g. vector[string]?
                    type_of_list = match(r'(\w+)\[(\w+)\]', self.types[index]).group(2) #get 'string
                    temp_list = []
                    for single_value in value.split(self.parameters_dict['set_separator']):
                        temp_list.append(self.__type_convert(type_of_list, single_value))
                    entry[index] = temp_list
                else:
                    entry[index] = self.__type_convert(self.types[index], value)
            return dict(zip(self.parameters_dict['fields'], entry))



    def __type_convert(self, bro_type, value):
        ''' Returns the python equivilant data type from Bro Data types'''
        if value in [self.empty_field, self.unset_field]:
            return None
        elif bro_type == 'string':
            return value
        elif bro_type == 'time':
            if self.datetime_to_isoformat:
                return datetime.fromtimestamp(float(value)).isoformat()
            else:
                return datetime.fromtimestamp(float(value))
        elif bro_type == 'interval':
            return float(value)
        elif bro_type in ['port', 'count', 'int']:
            return int(value)
        elif bro_type == 'bool':
            if value == 'F':
                return False
            elif value == 'T':
                return True
        else:
            return value

    def close(self):
        ''' Close the opened log file'''
        if self.log_file:
            self.log_file.close()


def create_logstash_conf(brolog):
    skeleton = '''
### INPUT BLOCK ###
input {{
    file {{
        type => "{path}"
        start_position => "beginning"

        # EDIT THIS LINE #
        path => "/usr/local/bro/logs/current/{path}.log"
    }}
}}

### FILTER BLOCK ###
filter {{
  if [message] =~ /^#/ {{
    drop {{ }}
  }}

}}

### OUTPUT BLOCK ###
output {{
    
}}
    '''.format(**vars(brolog))
    return skeleton
    
