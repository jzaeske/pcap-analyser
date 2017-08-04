#!/usr/bin/python3
# Fügt eine Ascii-Interpretation von hexadezimalen Daten zu einer CSV Datei hinzu
# Aufruf: hexToAscii.py inputFile srcColumn dstColumn outputFile
# inputFile die die eingelesene Datei, outputFile die erzeugte Ausgabe
# srcColumn ist der Name der Spalte, in welcher ein hexadezimaler Wert gespeichert ist
# dstColumn ist der Name der Spalte, in welcher die ASCII Interpretation gespeichert wird.

import sys
import csv
from curses.ascii import isprint

output = sys.argv[len(sys.argv) - 1]

FILE = sys.argv[1]
SRC = sys.argv[2]
DST = sys.argv[3]
OUT = sys.argv[4]

def hextoascii(hex):
    s = ''.join([chr(int(''.join(c), 16)) for c in zip(hex[0::2],hex[1::2])])
    return ''.join(char if isprint(char) and char != ',' else '?' for char in s)

with open(FILE) as infile:
    reader = csv.DictReader(infile, delimiter=',', quotechar='"')
    with open(OUT, 'w') as outfile:
        fieldnames = [DST]
        for key in reader.fieldnames:
            fieldnames.append(key)
        writer = csv.DictWriter(outfile, fieldnames=sorted(fieldnames))
        writer.writeheader()
        for row in reader:
            row[DST] = hextoascii(row[SRC])
            writer.writerow(row)
