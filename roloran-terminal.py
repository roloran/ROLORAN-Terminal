#!/usr/bin/env python3

"""
ROLORAN Terminal to interact with RDCP-capable LoRa modem devices.

The ROLORAN Terminal uses a simple readline-based interface for interactive
Serial/UART input/output. It is mostly used for testing and debugging purposes.
Several settings are biased / hard-coded to match ROLORAN conventions, such
as the baud rate and the use of the most recent RDCP version.

Text read from the Serial input is written to stdout with moderate syntax
highlighting and optionally into a logfile. Interactive input is optionally
stored in a history file. Commands can also be injected via textfiles
matching the name scheme given in 'script_glob'.

To quit, enter a command such as 'stop' on a line by itself.

Received RDCP packets are dissected for analysis. The craft mode can be used
to create new RDCP packets. The commands 'interactive' and 'craft' can be
used to switch between those two modes.
"""

import threading
from time import sleep
import os
import re
import glob

try:
    import gnureadline as readline
except ImportError:
    import readline

import sys
import serial
import datetime
import rdcpcodec

device = os.environ.get("LORADEV", "/dev/cu.usbmodem1201")
history_filename = ".lora_history"
log_filename = ".lora_logfile"
script_glob = "*.rterm"

enable_logfile = 1
enable_history = 1
script_line_delay = 1

abort_globally = 0
forced_exit = 0

color = {
    "red": "\u001b[31m",
    "green": "\u001b[32m",
    "yellow": "\u001b[33m",
    "blue": "\u001b[34m",
    "magenta": "\u001b[35m",
    "cyan": "\u001b[36m",
    "normal": "\u001b[0m",
}

MODE_INTERACTIVE = 0x01
MODE_CRAFT = 0x02
current_mode = MODE_INTERACTIVE


def rterm_setup(filename):
    """Prepare filenames to use (device, history, logfile)"""
    global device
    global history_filename
    global log_filename

    candidates = []
    if not os.path.exists(filename):
        mypattern = r"/dev/*"
        regex = r"cu\.usb.*|ttyACM.*|usbserial.*"
        for fn in glob.glob(mypattern):
            if re.search(regex, fn):
                candidates.append(fn)

        print(
            color["red"] + "LORADEV (",
            filename,
            ") not correct. " + color["cyan"] + "\nPlease choose the device to use:",
            sep="",
        )
        for c, i in enumerate(candidates):
            print(
                color["cyan"],
                str(c),
                color["normal"],
                ". ",
                color["magenta"],
                i,
                sep="",
            )

        line = input(color["cyan"] + "Your choice? ")
        try:
            index = int(line)
            filename = candidates[index]
        except:
            print(color["red"] + "Invalid choice.")
            sys.exit(1)

    device = filename
    print(color["normal"] + "Device name: ", device, "for serial input/output.")

    suffix = device.replace("/", "_")
    history_filename += "." + suffix
    log_filename += "." + suffix

    print("History file:", history_filename)
    print("Logfile name:", log_filename, "\n")


def write_logfile(line):
    """Append a line of text to the logfile"""
    global log_filename
    global enable_logfile

    if enable_logfile == 1:
        with open(log_filename, "a") as f:
            f.write(line + "\n")


def craft(cmd):
    """Execute a command in CRAFT mode"""
    to_print = ""
    to_send = ""

    if cmd.startswith("clear"):
        rdcpcodec.craft_clear()
    elif cmd.startswith("sender"):
        a = 0
        try:
            a = int(cmd[7:], 16)
        except:
            pass
        rdcpcodec.craft_sender(a)
    elif cmd.startswith("origin"):
        a = 0
        try:
            a = int(cmd[7:], 16)
        except:
            pass
        rdcpcodec.craft_origin(a)
    elif cmd.startswith("destination"):
        a = 0
        try:
            a = int(cmd[12:], 16)
        except:
            pass
        rdcpcodec.craft_destination(a)
    elif cmd.startswith("seq"):
        a = 0
        try:
            a = int(cmd[4:], 0)
        except:
            pass
        rdcpcodec.craft_seqnr(a)
    elif cmd.startswith("type"):
        rdcpcodec.craft_type(cmd[5:])
    elif cmd.startswith("length"):
        a = 0
        try:
            a = int(cmd[7:], 0)
        except:
            pass
        rdcpcodec.craft_length(a)
    elif cmd.startswith("count"):
        a = 0
        try:
            a = int(cmd[6:], 0)
        except:
            pass
        rdcpcodec.craft_count(a)
    elif cmd.startswith("relay1"):
        a = 0
        try:
            a = int(cmd[7:], 16)
        except:
            pass
        rdcpcodec.craft_relay1(a)
    elif cmd.startswith("relay2"):
        a = 0
        try:
            a = int(cmd[7:], 16)
        except:
            pass
        rdcpcodec.craft_relay2(a)
    elif cmd.startswith("relay3"):
        a = 0
        try:
            a = int(cmd[7:], 16)
        except:
            pass
        rdcpcodec.craft_relay3(a)
    elif cmd.startswith("crc"):
        rdcpcodec.craft_crc(cmd)
    elif cmd.startswith("payload"):
        rdcpcodec.craft_payload(cmd)
    elif cmd.startswith("print") or cmd.startswith("show"):
        rdcpcodec.craft_print()
    elif cmd.startswith("tx"):
        b64 = rdcpcodec.craft_getbase64()
        to_send = "TX " + b64
    elif cmd.startswith("simrx"):
        b64 = rdcpcodec.craft_getbase64()
        to_send = "SIMRX " + b64
    elif cmd.startswith("save"):
        rdcpcodec.craft_save(cmd)
    elif cmd.startswith("load"):
        rdcpcodec.craft_load(cmd)
    elif cmd.startswith("parse"):
        rdcpcodec.craft_parse(cmd)
    elif cmd.startswith("uselast"):
        rdcpcodec.craft_uselast()
    else:
        print(
            color["red"]
            + "Valid craft commands: clear, sender, origin, destination, seq, type, length, count, relay1, relay2, relay3, crc, payload, print, save, load, parse, uselast, interactive, tx, simrx"
            + color["normal"]
        )

    return to_print, to_send


def keyboard_thread():
    """Handle interactive keyboard input"""
    global abort_globally
    global forced_exit
    global ser
    global current_mode

    while True:
        if abort_globally == 1:
            break
        line = ""
        mycolor = "normal"
        if current_mode == MODE_INTERACTIVE:
            mycolor = "cyan"
        else:
            mycolor = "magenta"
        try:
            line = input(color[mycolor] + "> ")
        except:
            break
        if line == "stop" or line == "quit" or line == "exit":
            print(color["red"] + "Stopping terminal application...")
            forced_exit = 1
            break
        if abort_globally == 0:
            if current_mode == MODE_INTERACTIVE:
                if line == "craft":
                    current_mode = MODE_CRAFT
                    print(color["magenta"] + "Switching to CRAFT mode...")
                else:
                    line += "\n"
                    ser.write(str.encode(line))
            else:
                if line == "interactive":
                    current_mode = MODE_INTERACTIVE
                    print(color["cyan"] + "Switching to INTERACTIVE mode...")
                else:
                    to_print, to_send = craft(line)
                    if (len(to_print)) != 0:
                        print(to_print)
                    if (len(to_send)) != 0:
                        ser.write(str.encode(to_send))
    abort_globally = 1


def modem_thread():
    """Handle Serial/UART communication with the LoRa device"""
    global abort_globally
    global forced_exit
    global ser
    global device

    while True:
        line = ""
        if abort_globally == 1:
            ser.close()
            break
        try:
            line = ser.readline()
            if len(line) > 1:
                l = line.decode().strip()
                original_line = l
                sys.stdout.write("\r\x1b[K")
                ct = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                logfile_line = "[" + ct + "] " + l
                write_logfile(logfile_line)
                l = color["normal"] + logfile_line
                regex = (
                    r"^([a-zA-Z0-9-{} !?:]+: )(ECHO: |INFO: |WARNING: |ERROR: |RXMETA |RX |TXMETA |TX ).*$"
                )
                if re.search(regex, original_line):
                    l = l.replace("INFO:", color["yellow"] + "INFO:" + color["normal"])
                    l = l.replace("ECHO:", color["magenta"] + "ECHO:" + color["normal"])
                    l = l.replace(
                        "WARNING:", color["red"] + "WARNING:" + color["normal"]
                    )
                    l = l.replace("ERROR:", color["red"] + "ERROR:" + color["normal"])
                    l = l.replace(
                        "RXMETA ", color["green"] + "RXMETA " + color["normal"]
                    )
                    l = l.replace(
                        ": RX ", ": " + color["green"] + "RX " + color["normal"]
                    )
                    l = l.replace(
                        "TXMETA ", color["cyan"] + "TXMETA " + color["normal"]
                    )
                    l = l.replace(
                        ": TX ", ": " + color["cyan"] + "TX " + color["normal"]
                    )
                print(l)
                readline.redisplay()
        except:
            abort_globally = 1
            print(color["red"] + "Serial read failed - lost connection?")
            ser.close()
            while True:
                try:
                    print(color["red"] + "Attempting to reconnect...")
                    ser = serial.Serial(port=device, baudrate=115200, timeout=1)
                    print(color["green"] + "Reconnected")
                    abort_globally = 0
                    break
                except:
                    sleep(1)
                    if forced_exit == 1:
                        break
            if abort_globally == 1:
                break
        pos = str(line).find("RX ")
        if pos != -1:
            sys.stdout.write("\r\x1b[K")
            line = line.rstrip()
            rdcpcodec.rx_verbose(str(line))
            readline.redisplay()
        pos = str(line).find("TX ")
        if pos != -1:
            sys.stdout.write("\r\x1b[K")
            line = line.rstrip()
            rdcpcodec.tx_verbose(str(line))
            readline.redisplay()


def script_thread():
    """Watch the file system for new script files to inject"""
    global abort_globally
    global forced_exit
    global script_glob
    global ser
    global script_line_delay
    while True:
        if forced_exit == 1:
            break
        if abort_globally == 1:
            break
        sleep(1)
        for fn in glob.glob(script_glob):
            with open(fn, "r") as f:
                sys.stdout.write("\r\x1b[K")
                print(color["magenta"] + "Injecting script " + fn + "...")
                for l in f:
                    print("> " + l, end="")
                    ser.write(str.encode(l))
                    sleep(script_line_delay)
                readline.redisplay()
            os.rename(fn, fn + ".done")


if __name__ == "__main__":
    print("ROLORAN Terminal")
    print(" ")
    rterm_setup(os.environ.get("LORADEV", "/dev/ttyACM0"))

    try:
        ser = serial.Serial(port=device, baudrate=115200, timeout=1)
    except:
        print(
            color["red"]
            + "Cannot open device "
            + device
            + ", set LORADEV environment variable to proper filename!"
        )
        sys.exit(1)

    try:
        readline.read_history_file(history_filename)
    except:
        pass

    t1 = threading.Thread(target=keyboard_thread)
    t2 = threading.Thread(target=modem_thread)
    t3 = threading.Thread(target=script_thread)
    t1.start()
    t2.start()
    t3.start()
    t1.join()
    t2.join()
    t3.join()

    if enable_history == 1:
        readline.write_history_file(history_filename)

    sys.exit(0)

# EOF
