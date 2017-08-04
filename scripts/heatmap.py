#!/usr/bin/python3
# Generiert eine Heatmap für einen CSV Report der Analysesoftware
# Aufruf: heatmap.py eingabeDatei.csv cidr indexColumn valueColumn
# cidr gibt an, wie groß Das Subnetz ist, welches pro Punkt der Heatmap zusammengefasst werden soll
# indexColumn ist der Name der Spalte, in welcher sich die IP, oder das Subnetz der Messung befindet
# valueColumn ist die Spalte, welche die Anzahl von Paketen/Verbindungen/Bytes enthält, nach denen die Heatmap gewichtet wird
# Optional können übergeben werden:
# log (numerisch), um die Gewichtung um den Logarithmus zur Basis log zu manipulieren
# bin (als String), um die Gewichtung zu deaktiven.

import sys
import csv
import ipaddress
import math

import numpy as np
import matplotlib.pyplot as plt


if len(sys.argv) < 5:
    print("not enough arguments")
    sys.exit()

FILE = sys.argv[1]
CIDR = sys.argv[2]
indexColumn = sys.argv[3]
valueColumn = sys.argv[4]
log = 0
bin = False
if len(sys.argv) > 5 :
    log = int(sys.argv[5])
if len(sys.argv) > 6 and sys.argv[6] == 'bin':
    bin = True

OUTPUT = FILE.replace('.csv', '_' + CIDR + ("_bin" if bin else '') + '.png')

def iptoindex(ip, cidr):
    # map to target cidr
    ip = ip.split("/")[0] + "/" + cidr
    interface = ipaddress.IPv4Interface(ip)
    # get numerical value for network ip
    num = interface.network.network_address._ip
    # normalize to cidr
    return num // 2**(32 - int(cidr))

values =  []
valuesX = []
valuesY = []

binCheck = []

perDimension = 2 ** (int(CIDR) // 2)
maxX = 0
maxY = 0
with open(FILE) as infile:
    # print(perDimension)
    reader = csv.DictReader(infile, delimiter=',', quotechar='"')
    for row in reader:
        index = iptoindex(row[indexColumn], CIDR)
        if bin :
            if index in binCheck:
                continue
            binCheck.append(index)
        value = int(row[valueColumn])
        if log != 0:
            values.append(math.log(value, log))
        else:
            values.append(value)
        x = index % perDimension
        y = index // perDimension
        maxX = max(x, maxX)
        maxY = max(y, maxY)
        valuesX.append(x)
        valuesY.append(y)
        # print(row[indexColumn], index // perDimension, index % perDimension,)

for fill in range(maxY+1, maxX+1):
    valuesY.append(fill)
    valuesX.append(0)
    values.append(0)

if bin:
    heatmap, xedges, yedges = np.histogram2d(valuesX, valuesY, bins=perDimension)
else:
    heatmap, xedges, yedges = np.histogram2d(valuesX, valuesY, bins=perDimension, weights = values)
extent = [0, perDimension, 0, perDimension]

fig = plt.figure()
ax = fig.add_subplot(1, 1, 1)
map = ax.imshow(heatmap.T, cmap='Reds', interpolation='nearest', extent=extent, origin='lower')

xtics = []
ytics = []
xlabels = []
ylabels = []
for i in range(0, int(CIDR) // 2):
    numeric = int((i / (int(CIDR) // 2))  * (2 ** (int(CIDR) // 2)))
    ytics.append(numeric)
    yvalue = ipaddress.IPv4Address(numeric * 2** (32 - int(CIDR) // 2))
    ylabels.append(yvalue)

    if i % 2 == 1:
        xtics.append(numeric)
        xvalue = ipaddress.IPv4Address(numeric * 2** (32 - int(CIDR)))
        xlabels.append(xvalue)

ax.set_xticks(xtics)
ax.set_yticks(ytics)
ax.set_xticklabels(xlabels)
ax.set_yticklabels(ylabels)

fig.colorbar(map, ax=ax)

# Save the full figure...
fig.savefig(OUTPUT)
