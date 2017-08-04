#!/usr/bin/python3
# Analysiert verschiedene Werte für TLS Datenverkehr. Arbeitet auf der Ausgabe eines CSVStreamOutput
# Eingabe sind alle csv.gz Dateien des aktuellen Verzeichnisses
import os
import io
import sys
import csv
import gzip
from curses.ascii import isprint

counters = {
    'recordTypes': {},
    'versions': {},
    'handshakes': {},
    'ciphers': {},
    'compressionLengths': {},
    'compressions': {}
}

recordTypes = {
20: 'Change Cipher Spec',
21: 'Alert',
22: 'Handshake',
23: 'Application Data'
}

versions = {
'0100': 'SSL 1.0',
'0200': 'SSL 2.0',
'0300': 'SSL 3.0',
'0301': 'TLS 1',
'0302': 'TLS 1.1',
'0303': 'TLS 1.2',
}

handshakeTypes = {
0: 'hello_request',
1: 'client_hello',
2: 'server_hello',
11: 'certificate',
12: 'server_key_exchange',
13: 'certificate_request',
14: 'server_hello_done',
15: 'certificate_verify',
16: 'client_key_exchange',
20: 'finished',
255: '',
}

compressions = {
0: 'NULL',
1: 'DEFLATE',
64:	'LZS'
}

ciphers = {
0x0000:	'TLS_NULL_WITH_NULL_NULL',
0x0001:	'TLS_RSA_WITH_NULL_MD5',
0x0002:	'TLS_RSA_WITH_NULL_SHA',
0x0003:	'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
0x0004:	'TLS_RSA_WITH_RC4_128_MD5',
0x0005:	'TLS_RSA_WITH_RC4_128_SHA',
0x0006:	'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
0x0007:	'TLS_RSA_WITH_IDEA_CBC_SHA',
0x0008:	'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
0x0009:	'TLS_RSA_WITH_DES_CBC_SHA',
0x000A:	'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
0x000B:	'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA',
0x000C:	'TLS_DH_DSS_WITH_DES_CBC_SHA',
0x000D:	'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA',
0x000E:	'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA',
0x000F:	'TLS_DH_RSA_WITH_DES_CBC_SHA',
0x0010:	'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA',
0x0011:	'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
0x0012:	'TLS_DHE_DSS_WITH_DES_CBC_SHA',
0x0013:	'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
0x0014:	'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
0x0015:	'TLS_DHE_RSA_WITH_DES_CBC_SHA',
0x0016:	'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
0x0017:	'TLS_DH_Anon_EXPORT_WITH_RC4_40_MD5',
0x0018:	'TLS_DH_Anon_WITH_RC4_128_MD5',
0x0019:	'TLS_DH_Anon_EXPORT_WITH_DES40_CBC_SHA',
0x001A:	'TLS_DH_Anon_WITH_DES_CBC_SHA',
0x001B:	'TLS_DH_Anon_WITH_3DES_EDE_CBC_SHA',
0x001C:	'SSL_FORTEZZA_KEA_WITH_NULL_SHA',
0x001D:	'SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA',
0x001E:	'TLS_KRB5_WITH_DES_CBC_SHA',
0x001F:	'TLS_KRB5_WITH_3DES_EDE_CBC_SHA',
0x0020:	'TLS_KRB5_WITH_RC4_128_SHA',
0x0021:	'TLS_KRB5_WITH_IDEA_CBC_SHA',
0x0022:	'TLS_KRB5_WITH_DES_CBC_MD5',
0x0023:	'TLS_KRB5_WITH_3DES_EDE_CBC_MD5',
0x0024:	'TLS_KRB5_WITH_RC4_128_MD5',
0x0025:	'TLS_KRB5_WITH_IDEA_CBC_MD5',
0x0026:	'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA',
0x0027:	'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA',
0x0028:	'TLS_KRB5_EXPORT_WITH_RC4_40_SHA',
0x0029:	'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5',
0x002A:	'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5',
0x002B:	'TLS_KRB5_EXPORT_WITH_RC4_40_MD5',
0x002C:	'TLS_PSK_WITH_NULL_SHA',
0x002D:	'TLS_DHE_PSK_WITH_NULL_SHA',
0x002E:	'TLS_RSA_PSK_WITH_NULL_SHA',
0x002F:	'TLS_RSA_WITH_AES_128_CBC_SHA',
0x0030:	'TLS_DH_DSS_WITH_AES_128_CBC_SHA',
0x0031:	'TLS_DH_RSA_WITH_AES_128_CBC_SHA',
0x0032:	'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
0x0033:	'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
0x0034:	'TLS_DH_Anon_WITH_AES_128_CBC_SHA',
0x0035:	'TLS_RSA_WITH_AES_256_CBC_SHA',
0x0036:	'TLS_DH_DSS_WITH_AES_256_CBC_SHA',
0x0037:	'TLS_DH_RSA_WITH_AES_256_CBC_SHA',
0x0038:	'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
0x0039:	'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
0x003A:	'TLS_DH_Anon_WITH_AES_256_CBC_SHA',
0x003B:	'TLS_RSA_WITH_NULL_SHA256',
0x003C:	'TLS_RSA_WITH_AES_128_CBC_SHA256',
0x003D:	'TLS_RSA_WITH_AES_256_CBC_SHA256',
0x003E:	'TLS_DH_DSS_WITH_AES_128_CBC_SHA256',
0x003F:	'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',
0x0040:	'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
0x0041:	'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',
0x0042:	'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA',
0x0043:	'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA',
0x0044:	'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',
0x0045:	'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',
0x0046:	'TLS_DH_Anon_WITH_CAMELLIA_128_CBC_SHA',
0x0047:	'TLS_ECDH_ECDSA_WITH_NULL_SHA',
0x0048:	'TLS_ECDH_ECDSA_WITH_RC4_128_SHA',
0x0049:	'TLS_ECDH_ECDSA_WITH_DES_CBC_SHA',
0x004A:	'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
0x004B:	'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',
0x004C:	'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA',
0x0060:	'TLS_RSA_EXPORT1024_WITH_RC4_56_MD5',
0x0061:	'TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5',
0x0062:	'TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA',
0x0063:	'TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA',
0x0064:	'TLS_RSA_EXPORT1024_WITH_RC4_56_SHA',
0x0065:	'TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA',
0x0066:	'TLS_DHE_DSS_WITH_RC4_128_SHA',
0x0067:	'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
0x0068:	'TLS_DH_DSS_WITH_AES_256_CBC_SHA256',
0x0069:	'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',
0x006A:	'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
0x006B:	'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
0x006C:	'TLS_DH_Anon_WITH_AES_128_CBC_SHA256',
0x006D:	'TLS_DH_Anon_WITH_AES_256_CBC_SHA256',
0x0080:	'TLS_GOSTR341094_WITH_28147_CNT_IMIT',
0x0081:	'TLS_GOSTR341001_WITH_28147_CNT_IMIT',
0x0082:	'TLS_GOSTR341094_WITH_NULL_GOSTR3411',
0x0083:	'TLS_GOSTR341001_WITH_NULL_GOSTR3411',
0x0084:	'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA',
0x0085:	'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA',
0x0086:	'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA',
0x0087:	'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',
0x0088:	'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
0x0089:	'TLS_DH_Anon_WITH_CAMELLIA_256_CBC_SHA',
0x008A:	'TLS_PSK_WITH_RC4_128_SHA',
0x008B:	'TLS_PSK_WITH_3DES_EDE_CBC_SHA',
0x008C:	'TLS_PSK_WITH_AES_128_CBC_SHA',
0x008D:	'TLS_PSK_WITH_AES_256_CBC_SHA',
0x008E:	'TLS_DHE_PSK_WITH_RC4_128_SHA',
0x008F:	'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA',
0x0090:	'TLS_DHE_PSK_WITH_AES_128_CBC_SHA',
0x0091:	'TLS_DHE_PSK_WITH_AES_256_CBC_SHA',
0x0092:	'TLS_RSA_PSK_WITH_RC4_128_SHA',
0x0093:	'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA',
0x0094:	'TLS_RSA_PSK_WITH_AES_128_CBC_SHA',
0x0095:	'TLS_RSA_PSK_WITH_AES_256_CBC_SHA',
0x0096:	'TLS_RSA_WITH_SEED_CBC_SHA',
0x0097:	'TLS_DH_DSS_WITH_SEED_CBC_SHA',
0x0098:	'TLS_DH_RSA_WITH_SEED_CBC_SHA',
0x0099:	'TLS_DHE_DSS_WITH_SEED_CBC_SHA',
0x009A:	'TLS_DHE_RSA_WITH_SEED_CBC_SHA',
0x009B:	'TLS_DH_Anon_WITH_SEED_CBC_SHA',
0x009C:	'TLS_RSA_WITH_AES_128_GCM_SHA256',
0x009D:	'TLS_RSA_WITH_AES_256_GCM_SHA384',
0x009E:	'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
0x009F:	'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
0x00A0:	'TLS_DH_RSA_WITH_AES_128_GCM_SHA256',
0x00A1:	'TLS_DH_RSA_WITH_AES_256_GCM_SHA384',
0x00A2:	'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256',
0x00A3:	'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',
0x00A4:	'TLS_DH_DSS_WITH_AES_128_GCM_SHA256',
0x00A5:	'TLS_DH_DSS_WITH_AES_256_GCM_SHA384',
0x00A6:	'TLS_DH_Anon_WITH_AES_128_GCM_SHA256',
0x00A7:	'TLS_DH_Anon_WITH_AES_256_GCM_SHA384',
0x00A8:	'TLS_PSK_WITH_AES_128_GCM_SHA256',
0x00A9:	'TLS_PSK_WITH_AES_256_GCM_SHA384',
0x00AA:	'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256',
0x00AB:	'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384',
0x00AC:	'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256',
0x00AD:	'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384',
0x00AE:	'TLS_PSK_WITH_AES_128_CBC_SHA256',
0x00AF:	'TLS_PSK_WITH_AES_256_CBC_SHA384',
0x00B0:	'TLS_PSK_WITH_NULL_SHA256',
0x00B1:	'TLS_PSK_WITH_NULL_SHA384',
0x00B2:	'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256',
0x00B3:	'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384',
0x00B4:	'TLS_DHE_PSK_WITH_NULL_SHA256',
0x00B5:	'TLS_DHE_PSK_WITH_NULL_SHA384',
0x00B6:	'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256',
0x00B7:	'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384',
0x00B8:	'TLS_RSA_PSK_WITH_NULL_SHA256',
0x00B9:	'TLS_RSA_PSK_WITH_NULL_SHA384',
0xC001:	'TLS_ECDH_ECDSA_WITH_NULL_SHA',
0xC002:	'TLS_ECDH_ECDSA_WITH_RC4_128_SHA',
0xC003:	'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
0xC004:	'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',
0xC005:	'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA',
0xC006:	'TLS_ECDHE_ECDSA_WITH_NULL_SHA',
0xC007:	'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
0xC008:	'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
0xC009:	'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
0xC00A:	'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
0xC00B:	'TLS_ECDH_RSA_WITH_NULL_SHA',
0xC00C:	'TLS_ECDH_RSA_WITH_RC4_128_SHA',
0xC00D:	'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA',
0xC00E:	'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA',
0xC00F:	'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA',
0xC010:	'TLS_ECDHE_RSA_WITH_NULL_SHA',
0xC011:	'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
0xC012:	'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
0xC013:	'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
0xC014:	'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
0xC015:	'TLS_ECDH_Anon_WITH_NULL_SHA',
0xC016:	'TLS_ECDH_Anon_WITH_RC4_128_SHA',
0xC017:	'TLS_ECDH_Anon_WITH_3DES_EDE_CBC_SHA',
0xC018:	'TLS_ECDH_Anon_WITH_AES_128_CBC_SHA',
0xC019:	'TLS_ECDH_Anon_WITH_AES_256_CBC_SHA',
0xC01A:	'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA',
0xC01B:	'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA',
0xC01C:	'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA',
0xC01D:	'TLS_SRP_SHA_WITH_AES_128_CBC_SHA',
0xC01E:	'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA',
0xC01F:	'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA',
0xC020:	'TLS_SRP_SHA_WITH_AES_256_CBC_SHA',
0xC021:	'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA',
0xC022:	'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA',
0xC023:	'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
0xC024:	'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
0xC025:	'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
0xC026:	'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
0xC027:	'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
0xC028:	'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
0xC029:	'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256',
0xC02A:	'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',
0xC02B:	'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
0xC02C:	'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
0xC02D:	'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
0xC02E:	'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
0xC02F:	'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
0xC030:	'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
0xC031:	'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',
0xC032:	'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',
0xC033:	'TLS_ECDHE_PSK_WITH_RC4_128_SHA',
0xC034:	'TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA',
0xC035:	'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA',
0xC036:	'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA',
0xC037:	'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
0xC038:	'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384',
0xC039:	'TLS_ECDHE_PSK_WITH_NULL_SHA',
0xC03A:	'TLS_ECDHE_PSK_WITH_NULL_SHA256',
0xC03B:	'TLS_ECDHE_PSK_WITH_NULL_SHA384',
0xFEFE:	'SSL_RSA_FIPS_WITH_DES_CBC_SHA',
0xFEFF:	'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA',
0xFFE0:	'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA',
0xFFE1:	'SSL_RSA_FIPS_WITH_DES_CBC_SHA',
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
    return ''.join(char if isprint(char) and char != ',' else '?' for char in s)

def handlePayload(hexPayload):
    if len(hexPayload) > 0:
        recordType = int(hexPayload[0:2], 16)
        if recordType in recordTypes:
            incrementCount('recordTypes', recordTypes[recordType])
        else:
            incrementCount('recordTypes', 'no')
            return

        version = hexPayload[2:6]
        if version in versions:
            incrementCount('versions', version)
        else:
            incrementCount('versions', 'no')

        # Handshake
        if recordType == 22:
            handshakeType = int(hexPayload[10:12], 16)
            if handshakeType in handshakeTypes:
                incrementCount('handshakes', handshakeTypes[handshakeType])
            else:
                incrementCount('handshakes', 'unknown')

            # Client Hello
            if handshakeType == 1:
                hello = hexPayload[12:]
                # 3 byte length, 2 byte version, 32 byte random: skip
                data = hello[74:]
                # prefix notation 1 byte length, folloed by numeered entries
                idLength = int(data[0:2], 16)
                # 2 bytes length info + actual id
                data = data[2+idLength*2:]
                if len(data) > 2:
                    cipherLength = int(data[0:4], 16) // 2
                    data = data[4:]
                    if cipherLength == 0:
                        incrementCount('ciphers', 'no')
                    else :
                        for i in range (cipherLength):
                            cipher = int(data[0:4], 16)
                            if cipher in ciphers:
                                incrementCount('ciphers', ciphers[cipher])
                            else:
                                incrementCount('ciphers', cipher)
                            data = data[4:]
                if len(data) > 0:
                    compressionLength = int(data[0:2], 16) - 1
                    data = data[2:]
                    incrementCount('compressionLengths', compressionLength)
                    if compressionLength > 0:
                        for i in range(compressionLength):
                            compression = int(data[0:2], 16)
                            data = data[2:]
                            if compression in compressions:
                                incrementCount('compressions', compressions[compression])
                            else:
                                incrementCount('compressions', 'unknown')
    else:
        incrementCount('recordTypes', 'nopl')

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

print(counters)

# with open(FILE) as infile:
#
#     with open(OUT, 'w') as outfile:
#         fieldnames = [DST]
#         for key in reader.fieldnames:
#             fieldnames.append(key)
#         writer = csv.DictWriter(outfile, fieldnames=sorted(fieldnames))
#         writer.writeheader()
#         for row in reader:
#             row[DST] = iptonum(row[SRC])
#             writer.writerow(row)
