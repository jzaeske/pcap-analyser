#!/usr/bin/python3
# Fügt eine numerische Interpretation einer IP Adresse oder eines IP Subnetzes zu einer CSV Datei hinzu
# Aufruf: ip2Num.py inputFile srcColumn dstColumn outputFile
# inputFile die die eingelesene Datei, outputFile die erzeugte Ausgabe
# srcColumn ist der Name der Spalte, in welcher die IP gespeichert ist
# dstColumn ist der Name der Spalte, in welcher der numerische Wert gespeichert wird.
# Der numerische Wert wird beispielsweise für den Abgleich mit GeoIP Datenbanken benötigt.

import sys
import csv

output = sys.argv[len(sys.argv) - 1]

FILE = sys.argv[1]
SRC = sys.argv[2]
DST = sys.argv[3]
OUT = sys.argv[4]

def iptonum(ip):
    ip = ip.split("/")[0]
    i = 3
    result = 0
    for part in ip.split("."):
        result += int(part) * 2**(8*i)
        i -= 1
    return result

with open(FILE) as infile:
    reader = csv.DictReader(infile, delimiter=',', quotechar='"')
    with open(OUT, 'w') as outfile:
        fieldnames = [DST]
        for key in reader.fieldnames:
            fieldnames.append(key)
        writer = csv.DictWriter(outfile, fieldnames=sorted(fieldnames))
        writer.writeheader()
        for row in reader:
            row[DST] = iptonum(row[SRC])
            writer.writerow(row)
