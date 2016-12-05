from sys import argv
from os import path
from pybrolog import BroLog, create_logstash_conf

brolog = BroLog(path.abspath(argv[1]))
filename = brolog.path + ".conf"

with open (filename, 'w') as outfile:
    outfile.write(create_logstash_conf(brolog))