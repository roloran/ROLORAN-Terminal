#!/usr/bin/env python3

import os
import sys
import re

import argparse
from typing import Union

# Date regex format
REGEX_DATE = r'\d{4}-\d{2}-\d{2}'
REGEX_TIME = r'\d{2}:\d{2}:\d{2}'

# Regex to find any log line
REGEX_LOG_LINE_TIMESTAMP = rf'^\[({REGEX_DATE}) ({REGEX_TIME})\]'

# Regex to find any log line
REGEX_LOG_LINE = rf'{REGEX_LOG_LINE_TIMESTAMP} (.*)'

# Regex to find relevant log lines
REGEX_CSV_LINE = rf'{REGEX_LOG_LINE_TIMESTAMP}.*RDCPCSV: (.*)'

# Base file name for output files
BASE_FILE_NAME = "rdcp-log"

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
    elif rdcpa == "020A":
        result = "VS West"
    elif rdcpa == "020B":
        result = "VS Ost"
    elif rdcpa == "0010":
        result = "AutoHQ"
    elif rdcpa == "0001":
        result = "HQ Gemeinde"
    elif rdcpa == "0002":
        result = "HQ FF Neuhaus"
    elif rdcpa == "0003":
        result = "HQ FF Bach"
    elif rdcpa == "0004":
        result = "HQ FF Schwabegg"
    elif rdcpa == "0005":
        result = "HQ Reserve"
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
    elif mt == "0B":
        result = "Reset Dev"
    elif mt == "0C":
        result = "Reboot"
    elif mt == "0D":
        result = "Maintenance"
    elif mt == "0E":
        result = "Reset Infra"
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
    elif mt == "09":
        result = "BlockDev"
    elif mt == "11":
        result = "Reset OA"
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
    elif id == "A":
        result = "VS West"
    elif id == "B":
        result = "VS Ost"
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

def format_log_line_to_csv_line(line: str) -> Union[str,None]:

    valid_line = re.match(REGEX_CSV_LINE, line)
    # Filter non-csv lines
    if valid_line is None:
        return None
    else:
        date, timestamp, message = valid_line.groups()
        try:
            # Unpack CSV message
            device,sincelast,now,cfest,cfestrel,length,refnr,futts,sender,origin,seqnr,destination,mt,counter,r1,r2,r3,crc,airtime,frequency,rssi,snr = message.split(",")
        except ValueError:
            # Highlight malformed lines
            return f"{date}, {timestamp}\n"

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

    if (timeslot == 8 or timeslot == 0) and frequency[0] == '8':
        timeslot = "single"

    content = [
        date,
        timestamp,
        now,
        sincelast + " ms",
        str(at+1000) + " ms",
        cfestrel + " ms",
        length + " bytes",
        airtime + " ms",
        rssi,
        snr,
        timeslot,
        counter,
        futts,
        origin,
        sender,
        relay1,
        relay2,
        relay3,
        mt,
        refnr,
        destination,
        seqnr,
        frequency,
        device
    ]

    return ",".join(list(map(str, content))) + "\n"

def format_log_line(line: str) -> str:

    valid_line = re.match(REGEX_LOG_LINE, line)
    if valid_line is None:
        return ""
    else:
        return line + "\n"

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Process RDCP log file and output CSV.')

    # Options for input files
    parser.add_argument('-i', '--input-file', type=str, help='Path to RDCP log file to process', required=True, action='store')
    parser.add_argument('-c', '--cleanup', action='store_true', help='Remove input log file after processing')

    # Options for output storage
    parser.add_argument('-s', '--store', action='store', help="Path to output folder for CSV file(s)")
    parser.add_argument('-k', '--keep', action='store', help='Path to output folder for processed log file')

    # Options for advanced output storage
    parser.add_argument('-n', '--name', action='store', help='Name for output files (date prefix is added automatically)')
    parser.add_argument('-d', '--daily', action='store_true', help='Splits output into multiple files based on date')
    parser.add_argument('-a', '--append', action='store_true', help='Append data to output files instead of overwriting (both for CSV and kept log file)')

    args = parser.parse_args()

    # Check if input file exists
    if os.path.exists(args.input_file):
        logfile_name = args.input_file
    else:
        print("Log file does not exist:", args.input_file)
        sys.exit(0)

    # Extract relevant lines from log file
    csv_lines = []

    with open(logfile_name, 'r') as logfile:
        for line in logfile:
            csv_line = format_log_line_to_csv_line(line)
            if csv_line is not None:
                csv_lines.append(csv_line)

    # Create CSV header
    header = "Date,Time,Timestamp,SinceLast,TSduration,CFEstRel,Length,Airtime,RSSI,SNR,Timeslot,Counter,FutTS,Origin,Sender,Relay1,Relay2,Relay3,Type,RefNr,Destination,SeqNr,Frequency,Device"

    name = args.name if args.name else BASE_FILE_NAME

    # Check if output should be stored in files
    if args.store:

        # Check if output directory exists
        if not os.path.isdir(args.store):
            print("Output directory does not exist:", args.store)
            sys.exit(0)
        else:
            date_dict = {}

            # Check if output should be seprated by date
            if args.daily:
                for line in csv_lines:
                    date = line.split(",")[0]
                    if date not in date_dict:
                        date_dict[date] = []
                    date_dict[date].append(line)
            else:
                date_dict["all"] = csv_lines

            # Create output files
            for date, lines in date_dict.items():
                output_file = os.path.join(args.store, f"{date}-{name}.csv")

                # Check if output should be appended or overwritten
                if args.append and os.path.exists(output_file):
                    with open(output_file, 'a') as f:
                        f.writelines(csv_lines)
                else:
                    with open(output_file, 'w') as f:
                        f.write(header + "\n")
                        f.writelines(csv_lines)

    else:
        # Print to standard output
        print(header)
        for line in csv_lines:
            print(line, end='')

    # Check if log file should be saved
    if args.keep:
        
        # Check if directory exists
        if not os.path.isdir(args.keep):
            print("Keep directory does not exist:", args.keep)
            sys.exit(0)
        else:
            date_dict = {}

            # Read original log file
            with open(logfile_name, 'r') as logfile:
                log_lines = logfile.readlines()

                # Check if output should be seprated by date
                if args.daily:
                    for line in log_lines:
                        valid_line = re.match(REGEX_LOG_LINE, line)
                        if valid_line is not None:
                            if args.daily:
                                date = valid_line.group(1)
                                if date not in date_dict:
                                    date_dict[date] = []
                                date_dict[date].append(line)
                else:
                    date_dict["all"] = log_lines
                    
            # Create output files
            for date, lines in date_dict.items():
                output_file = os.path.join(args.keep, f"{date}-{name}.log")
                
                # Check if output should be appended or overwritten
                if args.append and os.path.exists(output_file):
                    with open(output_file, 'a') as f:
                        f.writelines(lines)
                else:
                    with open(output_file, 'w') as f:
                        f.writelines(lines)

    # Check if log file should be removed
    if args.cleanup and os.path.exists(logfile_name):
        os.remove(logfile_name)

    sys.exit(0)

    # EOF
