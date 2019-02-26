'''

Implementation of MS-SNTP(Authenticator) in python 3.

*validate checksum is not done yet.

'''

from socket import AF_INET, SOCK_DGRAM
from binascii import hexlify, unhexlify
import time
import socket
import hashlib
import struct
import numpy

#  Send 48 or 68 bytes request to the DC.
def ntpclientrequest(ip, payload):
    read_buffer = 1024
    ntp = socket.socket(AF_INET, SOCK_DGRAM)
    ntp.sendto(payload, (ip, 123))
    buf, address = ntp.recvfrom(read_buffer)
    ntp.close()
    return buf

#  Unpack date from the server response.
def unpackdate(payload):
    epoch = 2208988800
    t = struct.unpack("!12I", payload[:48])[10]
    t -= epoch
    return t

#  Create payload that will be used by us when sending the ntp request.
def pdata(rid=None):
    try:
        rid = numpy.uint32(rid)
        data = (b'\x1b' + 47 * b'\0' + rid + 16 * b'\0')
    except TypeError:
        data = (b'\x1b' + 47 * b'\0')
    return data


hosts = [b'DC01', b'DC02', b'DC03']

for host in hosts:
    response = ntpclientrequest(host, pdata(8581))
    date = (unpackdate(response))
    print(host, time.ctime(date), len(hexlify(response)))


