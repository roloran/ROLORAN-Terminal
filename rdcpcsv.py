#!/usr/bin/env python3

import datetime
import rdcpcodec
import sys
import re

def getname(rdcpa):
    result = "0x" + rdcpa
    if rdcpa == "0200":
        result = "Neuhaus"
    elif rdcpa == "0201":
        result = "Illmitzen oben"
    elif rdcpa == "0202":
        result = "Illmitzen unten"
    elif rdcpa == "0203":
        result = "Motschula"
    elif rdcpa == "0204":
          result = "Pudlach"
    elif rdcpa == "0205":
        result = "Schwabegg"
    elif rdcpa == "0206":
         result = "Heiligenstadt"
    elif rdcpa == "0207":
        result = "Wesnitzen"
    elif rdcpa == "0208":
        result = "Bach"
    elif rdcpa == "0209":
        result = "Berg ob Leifling"
    elif rdcpa == "0010":
        result = "AutoHQ"
    elif rdcpa == "00FF":
        result = "HQ Multicast"
    elif rdcpa == "FFFF":
        result = "Broadcast"
    return result


def getmt(mt):
    result = "0x" + mt
    if mt == "10":
        result = "Off. Ann."
    elif mt == "30":
        result = "Signature"
    elif mt == "31":
        result = "Heartbeat"
    elif mt == "0A":
        result = "Timestamp"
    elif mt == "0F":
        result = "ACK"
    elif mt == "05":
        result = "DAS REQ"
    elif mt == "1A":
        result = "CIRE"
    elif mt == "06":
        result = "DAS RESP"
    elif mt == "01":
        result = "PING"
    elif mt == "02":
        result = "PONG"
    elif mt == "20":
        result = "FETCHALL"
    elif mt == "2A":
        result = "RECEIPT"
    return result


def getrelaybyid(id):
    result = "unknown " + id
    if id == "0":
        result = "Neuhaus"
    elif id == "1":
        result = "Illmitzen oben"
    elif id == "2":
        result = "Illmitzen unten"
    elif id == "3":
        result = "Motschula"
    elif id == "4":
        result = "Pudlach"
    elif id == "5":
        result = "Schwabegg"
    elif id == "6":
        result = "Heiligenstadt"
    elif id == "7":
        result = "Wesnitzen"
    elif id == "8":
        result = "Bach"
    elif id == "9":
        result = "Berg ob Leifling"
    elif id == "C":
        result = "Config Fail"
    elif id == "D":
        result = "Don't know"
    elif id == "E":
        result = "Noone"
    elif id == "F":
        result = "Everyone"

    return result


def getrelay(sender, r1, r2, r3):
    res1 = "unknown " + r1
    res2 = "unknown " + r2
    res3 = "unknown " + r3

    sender_int = int(sender, 16)
    if (sender_int >= 0x0300 and sender_int <= 0xFEFF) or (sender_int >= 0x0001 and sender_int <= 0x00FF):
        if r2 == "EE" and r3 == "EE":
            res1 = "EP " + getrelaybyid(r1[0])
            res2 = "unused"
            res3 = "unused"
    else:
        res1 = "R " + getrelaybyid(r1[0]) + " D " + r1[1] + " (" + r1 + ")"
        res2 = "R " + getrelaybyid(r2[0]) + " D " + r2[1] + " (" + r2 + ")"
        res3 = "R " + getrelaybyid(r3[0]) + " D " + r3[1] + " (" + r3 + ")"

    return (res1, res2, res3)


def print_line(m1, m2):
    d, t = m1.split(" ")
    print(d, t, sep=",", end=",")

    device,sincelast,now,cfest,cfestrel,length,refnr,futts,sender,origin,seqnr,destination,mt,counter,r1,r2,r3,crc,airtime,frequency = m2.split(",")

    timeslot = 8 - int(futts)
    osender = sender
    sender = getname(sender)
    origin = getname(origin)
    destination = getname(destination)
    mt = getmt(mt)
    refnr = "0x" + refnr
    seqnr = "0x" + seqnr
    relay1, relay2, relay3 = getrelay(osender, r1, r2, r3)

    at = int(airtime)

    print(now, sincelast + " ms", str(at+1000) + " ms", cfestrel + " ms",
          length + " bytes", airtime + " ms", timeslot, counter, futts,
          origin, sender, relay1, relay2, relay3,
          mt, refnr,
          destination, seqnr,
          frequency, device, sep=",")

    return


# Main program

if len(sys.argv) < 2:
    print("Usage:", sys.argv[0], "logfilename")
    sys.exit(0)

logfile_name = sys.argv[1]

p = re.compile(r'^\[(.*)\].*RDCPCSV: (.*)')

with open(logfile_name, 'r') as logfile:
    print("Date,Time,Timestamp,SinceLast,TSduration,CFEstRel,Length,Airtime,Timeslot,Counter,FutTS,Origin,Sender,Relay1,Relay2,Relay3,Type,RefNr,Destination,SeqNr,Frequency,Device")
    for line in logfile:
        l = line.strip()
        m = p.match(l)
        if m != None:
            print_line(m.group(1), m.group(2))

sys.exit(0)

# EOF
