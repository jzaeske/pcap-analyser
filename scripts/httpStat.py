#!/usr/bin/python3
# Analysiert verschiedene Werte für HTTP Datenverkehr. Arbeitet auf der Ausgabe eines CSVStreamOutput
# Eingabe sind alle csv.gz Dateien des aktuellen Verzeichnisses

import os
import io
import sys
import csv
import gzip
import re
from curses.ascii import isprint

csv.field_size_limit(sys.maxsize)

request = re.compile('([A-Za-z]+) ?(.*) HTTP/([0-9\.]+)')
body = re.compile("$^$^(.+)", re.DOTALL | re.M)

counters = {
    'method': {},
    'path': {},
    'mpath': {},
    'version': {},
    'body': {}
}

def handleGzip(filename):
    print(filename)
    with gzip.open(filename) as csv:
        handleCsv(csv)

def handleCsv(file):
    reader = csv.DictReader(io.TextIOWrapper(file, newline=""), delimiter=',', quotechar='"')
    for row in reader:
        handlePayload(row['payload'])

def hextoascii(hex):
    s = ''.join([chr(int(''.join(c), 16)) for c in zip(hex[0::2],hex[1::2])])
    return s
    # return ''.join(char if isprint(char) and char != ',' else '?' for char in s)

def handlePayload(hexPayload):
    if len(hexPayload) > 0:
        ascii = hextoascii(hexPayload)
        m = request.match(ascii)
        if (m == None):
            incrementCount('method', 'nohttp')
            return

        method = m.group(1)
        path = m.group(2)
        version = m.group(3)

        incrementCount('method', method)
        incrementCount('path', path)
        incrementCount('version', version)
        incrementCount('mpath', method + ' ' + path)


    else:
        incrementCount('method', 'nopl')

def incrementCount(counter, count):
    if counter in counters:
        c = counters[counter]
    if count in c:
        c[count] += 1
    else:
         c[count] = 1

for filename in os.listdir("."):
    if filename.endswith(".csv.gz"):
        handleGzip(filename)

for m in counters.keys():
    with open('_summary_' + m + '.csv', 'w') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=['type', 'value'])
        c = counters[m]
        for key, value in c.items():
            writer.writerow({'type':key, 'value': value})
