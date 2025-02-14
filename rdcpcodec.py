#!/usr/bin/env python3

import base64

try:
    import gnureadline as readline
except ImportError:
    import readline
import unishox2
import re
import copy
import rdcp_v04
from cryptography.exceptions import InvalidKey, InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import schnorr
import hashlib

RDCP_HEADER_SIZE = 16

crafted_rdcp_msg = bytearray(b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")
last_message = ""

color = {
    "red": "\u001b[31m",
    "green": "\u001b[32m",
    "yellow": "\u001b[33m",
    "blue": "\u001b[34m",
    "magenta": "\u001b[35m",
    "cyan": "\u001b[36m",
    "normal": "\u001b[0m",
}

rdcp_msgtypes = {
    0x00: "RDCP Test",
    0x01: "RDCP Echo Request (PING)",
    0x02: "RDCP Echo Response (PONG)",
    0x03: "RDCP BBK Status Request",
    0x04: "RDCP BBK Status Response",
    0x05: "RDCP DA Status Request",
    0x06: "RDCP DA Status Response",
    0x07: "RDCP Traceroute Request",
    0x08: "RDCP Traceroute Response",
    0x0A: "RDCP Timestamp",
    0x0B: "RDCP Device Reset",
    0x0C: "RDCP Device Reboot",
    0x0D: "RDCP Device Maintenance",
    0x0E: "RDCP Reset Infrastructure",
    0x0F: "RDCP Acknowledgment",
    0x10: "RDCP Official Announcement",
    0x11: "RDCP Reset All Announcements",
    0x1A: "RDCP Citizen Report",
    0x1C: "RDCP Privileged Report",
    0x20: "RDCP Fetch All New Messages",
    0x21: "RDCP Fetch Message",
    0x2A: "RDCP Delivery Receipt",
    0x30: "RDCP Cryptographic Signature",
}


def hex_duo(b):
    """Convert a hex number into a two-digit uppercase hex string with 0x prefix"""
    hd = hex(b)[2:].upper()
    if len(hd) != 2:
        hd = "0" + hd
    return str("0x" + hd)


def print_hex_readable(bytes):
    """Print a received LoRa packet as both hexdump and human-readable ASCII string"""
    length = len(bytes)
    print(
        color["magenta"] + "RX decoded, length ",
        length,
        color["normal"] + ": ",
        sep="",
        end="",
    )
    readable = ""
    for b in range(0, length):
        hb = hex_duo(bytes[b])
        print(hb, end=" ")
        v = int(bytes[b])
        if v > 31 and v < 127:
            readable += "%c" % v
        else:
            readable += "."
    print(color["normal"])
    print(
        color["magenta"]
        + "... printable ASCII "
        + color["normal"]
        + " : "
        + readable
        + color["normal"]
    )


def craft_rdcp_from_message(m):
    """Create an RDCP message based on a given RDCP message"""
    rdcp = copy.copy(m)
    return bytearray(rdcp)


def craft_clear():
    """Create an empty RDCP Header"""
    global crafted_rdcp_msg
    crafted_rdcp_msg = bytearray()
    for i in range(16):
        crafted_rdcp_msg.append(0)
    pretty_print_rdcp(crafted_rdcp_msg, "magenta")
    return crafted_rdcp_msg


def craft_update_crc():
    """Set the proper CRC-16 for the crafted RDCP message"""
    global crafted_rdcp_msg
    data_for_crc = bytearray()
    data_for_crc.extend(crafted_rdcp_msg[:14])
    pl_h, pl_i = rdcp_get_payloadlength(crafted_rdcp_msg)
    if pl_i != 0:
        data_for_crc.extend(crafted_rdcp_msg[16:])
    real_crc = rdcp_v04.crc16(data_for_crc)
    crafted_rdcp_msg[14] = real_crc % 256
    crafted_rdcp_msg[15] = real_crc // 256
    return hex_quad(real_crc), real_crc


def craft_sender(a):
    """Update the sender header field in the crafted RDCP message"""
    global crafted_rdcp_msg
    crafted_rdcp_msg[0] = a % 256
    crafted_rdcp_msg[1] = a // 256
    craft_update_crc()
    pretty_print_rdcp(crafted_rdcp_msg, "magenta")
    return crafted_rdcp_msg


def craft_origin(a):
    """Update the origin header field in the crafted RDCP message"""
    global crafted_rdcp_msg
    crafted_rdcp_msg[2] = a % 256
    crafted_rdcp_msg[3] = a // 256
    craft_update_crc()
    pretty_print_rdcp(crafted_rdcp_msg, "magenta")
    return crafted_rdcp_msg


def craft_seqnr(a):
    """Update the sequence number header field in the crafted RDCP message"""
    global crafted_rdcp_msg
    crafted_rdcp_msg[4] = a % 256
    crafted_rdcp_msg[5] = a // 256
    craft_update_crc()
    pretty_print_rdcp(crafted_rdcp_msg, "magenta")
    return crafted_rdcp_msg


def craft_destination(a):
    """Update the destination header field in the crafted RDCP message"""
    global crafted_rdcp_msg
    crafted_rdcp_msg[6] = a % 256
    crafted_rdcp_msg[7] = a // 256
    craft_update_crc()
    pretty_print_rdcp(crafted_rdcp_msg, "magenta")
    return crafted_rdcp_msg


def craft_type(a):
    """Update the message type header field in the crafted RDCP message"""
    global crafted_rdcp_msg
    mytype = 0x00
    try:
        mt = int(a, 0)
        mytype = mt
    except:
        for k, v in rdcp_msgtypes.items():
            if a.upper() in v.upper():
                mytype = k
    crafted_rdcp_msg[8] = mytype
    craft_update_crc()
    pretty_print_rdcp(crafted_rdcp_msg, "magenta")
    return crafted_rdcp_msg


def craft_length(a):
    """Update the payload length header field in the crafted RDCP message"""
    global crafted_rdcp_msg
    crafted_rdcp_msg[9] = a % 256
    while len(crafted_rdcp_msg) < a:
        crafted_rdcp_msg.append(0x00)
    craft_update_crc()
    pretty_print_rdcp(crafted_rdcp_msg, "magenta")
    return crafted_rdcp_msg


def craft_count(a):
    """Update the retransmission counter header field in the crafted RDCP message"""
    global crafted_rdcp_msg
    crafted_rdcp_msg[10] = a % 256
    craft_update_crc()
    pretty_print_rdcp(crafted_rdcp_msg, "magenta")
    return crafted_rdcp_msg


def craft_relay1(a):
    """Update the relay1 header field in the crafted RDCP message"""
    global crafted_rdcp_msg
    crafted_rdcp_msg[11] = a % 256
    craft_update_crc()
    pretty_print_rdcp(crafted_rdcp_msg, "magenta")
    return crafted_rdcp_msg


def craft_relay2(a):
    """Update the relay2 header field in the crafted RDCP message"""
    global crafted_rdcp_msg
    crafted_rdcp_msg[12] = a % 256
    craft_update_crc()
    pretty_print_rdcp(crafted_rdcp_msg, "magenta")
    return crafted_rdcp_msg


def craft_relay3(a):
    """Update the relay3 header field in the crafted RDCP message"""
    global crafted_rdcp_msg
    crafted_rdcp_msg[13] = a % 256
    craft_update_crc()
    pretty_print_rdcp(crafted_rdcp_msg, "magenta")
    return crafted_rdcp_msg


def craft_crc(a):
    """Update the CRC header field in the crafted RDCP message"""
    global crafted_rdcp_msg
    try:
        c = int(a[4:], 16)
        crafted_rdcp_msg[14] = c % 256
        crafted_rdcp_msg[15] = c // 256
    except:
        craft_update_crc()
    pretty_print_rdcp(crafted_rdcp_msg, "magenta")
    return crafted_rdcp_msg


def craft_payload(a):
    """Update the RDCP payload in the crafted RDCP message"""
    global crafted_rdcp_msg
    if len(a) < 10:
        print(
            color["red"]
            + "Use either of payload clear, payload text, payload unishox2, payload hex, payload base64 ..."
            + color["normal"]
        )
    else:
        try:
            a = a[8:]
            if a.startswith("clear"):
                crafted_rdcp_msg = crafted_rdcp_msg[0:16]
                crafted_rdcp_msg[9] = 0x00
            elif a.startswith("text"):
                crafted_rdcp_msg = crafted_rdcp_msg[0:16]
                cnt = 0
                for c in a[5:]:
                    cnt = cnt + 1
                    crafted_rdcp_msg.append(ord(c))
                crafted_rdcp_msg[9] = cnt
            elif a.startswith("unishox2"):
                crafted_rdcp_msg = crafted_rdcp_msg[0:16]
                cnt = 0
                bytes, ol = unishox2.compress(a[9:])
                for b in range(0, len(bytes)):
                    cnt += 1
                    crafted_rdcp_msg.append(bytes[b])
                crafted_rdcp_msg[9] = cnt
            elif a.startswith("hex"):
                crafted_rdcp_msg = crafted_rdcp_msg[0:16]
                cnt = 0
                hexfield = a[4:]
                for x in range(0, len(hexfield) // 2):
                    value = 0
                    h1 = hexfield[2 * x]
                    h2 = hexfield[2 * x + 1]
                    try:
                        i1 = 16 * int(h1, 16)
                        i2 = int(h2, 16)
                        value = i1 + i2
                    except:
                        pass
                    crafted_rdcp_msg.append(value)
                    cnt += 1
                crafted_rdcp_msg[9] = cnt
            elif a.startswith("base64"):
                crafted_rdcp_msg = crafted_rdcp_msg[0:16]
                cnt = 0
                decoded = b""
                try:
                    decoded = base64.b64decode(a[7:])
                except:
                    pass
                for b in range(0, len(decoded)):
                    crafted_rdcp_msg.append(decoded[b])
                    cnt += 1
                crafted_rdcp_msg[9] = cnt
        except:
            pass

    craft_update_crc()
    pretty_print_rdcp(crafted_rdcp_msg, "magenta")
    return crafted_rdcp_msg


def craft_getbase64():
    """Convert the crafted RDCP message into a Base64-encoded string"""
    global crafted_rdcp_msg
    return str(base64.b64encode(crafted_rdcp_msg))[2:-1]


def craft_print():
    """Print the crafted message"""
    global crafted_rdcp_msg
    pretty_print_rdcp(crafted_rdcp_msg, "magenta")
    b64 = craft_getbase64()
    print(color["magenta"] + "RDCP Message b64 : " + color["normal"] + b64)
    return


def craft_save(cmd):
    """Save the currently crafted RDCP message to a file"""
    global crafted_rdcp_msg
    m = craft_getbase64()
    try:
        fn = cmd[5:]
        with open(".rterm-" + fn + ".craft", "w") as f:
            f.write(m + "\n")
        print(color["magenta"] + "Crafted message saved as " + fn + color["normal"])
    except:
        pass
    return


def craft_load(cmd):
    """Load a crafted RDCP message from a file"""
    global crafted_rdcp_msg
    try:
        fn = cmd[5:]
        b64 = ""
        with open(".rterm-" + fn + ".craft", "r") as f:
            lines = [line.rstrip() for line in f]
            b64 = lines[0]
        craft_parse("parse " + b64)
    except:
        print(color["red"] + "Loading failed" + color["normal"])
    return


def craft_parse(cmd):
    """Parse the currently crafted message from a base64-encoded string"""
    global crafted_rdcp_msg
    try:
        b64 = cmd[6:]
        decoded = base64.b64decode(b64)
        crafted_rdcp_msg = bytearray()
        for i in range(0, len(decoded)):
            crafted_rdcp_msg.append(decoded[i])
    except:
        print(color["red"] + "Parsing failed" + color["normal"])
    pretty_print_rdcp(crafted_rdcp_msg, "magenta")
    return


def craft_uselast():
    """Use the most recent received message as crafted message"""
    global crafted_rdcp_msg
    global last_message
    print(color["magenta"] + "Last message     :" + color["normal"], last_message)
    if len(last_message) > 5:
        craft_parse("parse " + last_message)
    return


def hex_quad(n):
    """Convert a hex number into a four-digit uppercase hex string with 0x prefix"""
    h = hex(n)[2:].upper()
    while len(h) < 4:
        h = "0" + h
    return "0x" + h


def rdcp_get_device_category(a):
    """Convert an RDCP address into a human-readable string (device name or category)"""
    c = "unknown"
    if a == 0x000:
        c = "reserved"
    elif a < 0x00FF:
        c = "HQ"
    elif a == 0x00FF:
        c = "HQ multicast"
    elif a < 0x0200:
        c = "BBK"
    elif a < 0x0300:
        c = "DA"
        if a == 0x0200:
            c = "DA Neuhaus"
        elif a == 0x0201:
            c = "DA Illmitzen 10"
        elif a == 0x0202:
            c = "DA Illmitzen 1"
        elif a == 0x0203:
            c = "DA Motschula"
        elif a == 0x0204:
            c = "DA Pudlach"
        elif a == 0x0205:
            c = "DA Schwabegg"
        elif a == 0x0206:
            c = "DA Heiligenstadt"
        elif a == 0x0207:
            c = "DA Wesnitzen"
        elif a == 0x0208:
            c = "DA Bach"
        elif a == 0x0209:
            c = "DA Berg ob Leifling"
    elif a < 0xAF00:
        c = "MG"
    elif a < 0xAFFF:
        c = "MG ROLORAN Team Test Device"
    elif a < 0xC000:
        c = "Group/Multicast Address"
    elif a < 0xFF00:
        c = "MG for Emergency Services"
    elif a < 0xFFFF:
        c = "reserved"
    elif a == 0xFFFF:
        c = "broadcast address"

    return c


def rdcp_get_sender(m):
    """Retrieve the sender RDCP address and device category from an RDCP message"""
    sender_address = int(m[0]) + 256 * int(m[1])
    return hex_quad(sender_address), rdcp_get_device_category(sender_address)


def rdcp_get_origin(m):
    """Retrieve the origin RDCP address and device category from an RDCP message"""
    origin_address = int(m[2]) + 256 * int(m[3])
    return hex_quad(origin_address), rdcp_get_device_category(origin_address)


def rdcp_get_seqnr(m):
    """Retrieve the sequence number as hex and decimal number from an RDCP message"""
    seqnr = int(m[4]) + 256 * int(m[5])
    return hex_quad(seqnr), seqnr


def rdcp_get_destination(m):
    """Retrieve the destination RDCP address and device category from an RDCP message"""
    destination = int(m[6]) + 256 * int(m[7])
    return hex_quad(destination), rdcp_get_device_category(destination)


def rdcp_get_messagetype(m):
    """Retrieve the message type as hex and decimal number from an RDCP message"""
    mt = int(m[8])
    mtr = "unknown message type"
    try:
        mtr = rdcp_msgtypes[mt]
    except:
        pass
    return hex_duo(mt), mtr


def rdcp_get_payloadlength(m):
    """Retrieve the payload length as hex and decimal number from an RDCP message"""
    pl = int(m[9])
    return hex_duo(pl), pl


def rdcp_get_counter(m):
    """Retrieve the retransmission counter as hex and decimal number from an RDCP message"""
    c = int(m[10])
    return hex_duo(c), c


def rdcp_get_relay1(m):
    """Retrieve the relay 1 / delay setting as hex and decimal number from an RDCP message"""
    r1 = int(m[11])
    return hex_duo(r1), r1


def rdcp_get_relay2(m):
    """Retrieve the relay 2 / delay setting as hex and decimal number from an RDCP message"""
    r2 = int(m[12])
    return hex_duo(r2), r2


def rdcp_get_relay3(m):
    """Retrieve the relay 3 / delay setting as hex and decimal number from an RDCP message"""
    r3 = int(m[13])
    return hex_duo(r3), r3


def rdcp_get_crc16(m):
    """Retrieve the CRC-16 checksum as hex and decimal number from an RDCP message"""
    crc16 = int(m[14]) + 256 * int(m[15])
    return hex_quad(crc16), crc16


def get_relay_and_delay(v):
    """Retrieve the designated relay and delay from a corresponding 8-bit RDCP header field"""
    r = (v & 0xF0) // 16
    d = v & 0x0F
    relay = "unknown relay"
    delay = "unknown delay"
    if r == 0x00:
        relay = "DA Neuhaus"
    elif r == 0x01:
        relay = "DA Illmitzen 10"
    elif r == 0x02:
        relay = "DA Illmitzen 1"
    elif r == 0x03:
        relay = "DA Motschula"
    elif r == 0x04:
        relay = "DA Pudlach"
    elif r == 0x05:
        relay = "DA Schwabegg"
    elif r == 0x06:
        relay = "DA Heiligenstadt"
    elif r == 0x07:
        relay = "DA Wesnitzen"
    elif r == 0x08:
        relay = "DA Bach"
    elif r == 0x09:
        relay = "DA Berg ob Leifling"
    elif r == 0x0E:
        relay = "None"
    elif r == 0x0F:
        relay = "Anyone"

    if d == 0x0E:
        delay = "do not relay"
    elif d == 0x0F:
        delay = "immediately"
    else:
        delay = "delay " + str(d)

    return relay, delay


def verify_crc16(m):
    """Verify the CRC-16 (CCITT) checksum in an RDCP message"""
    data_for_crc = bytearray()
    data_for_crc.extend(m[:14])
    pl_h, pl_i = rdcp_get_payloadlength(m)
    if pl_i != 0:
        data_for_crc.extend(m[16:])
    real_crc = rdcp_v04.crc16(data_for_crc)

    m_crc_h, m_crc_i = rdcp_get_crc16(m)

    return real_crc == m_crc_i


def getSharedSecret(origin):
    """Return the HQ Shared Secret AES-256 key for a CIRE origin if available, otherwise None """
    try:
        f = open("aeskey-" + origin, "r")
        content = f.readline()
        f.close()
        content = content.rstrip()
        b = bytes.fromhex(content)
        return b
    except:
        return None


def getSchnorrPublicKey():
    try:
        f = open("schnorr.pub", "r")
        content = f.readline()
        content = content.rstrip()
        f.close()
        return content
    except:
        print("ERROR: No local Schnorr Public Key found")
        return ""


def getSchnorrPrivateKey():
    try:
        f = open("schnorr.priv", "r")
        content = f.readline()
        content = content.rstrip()
        f.close()
        return content
    except:
        print("ERROR: No local Schnorr Private Key found")
        return ""

def getSchnorrVerification(rdcp, num_bytes):
    sch = schnorr.SchnorrSignature()
    pubkey_from_file = getSchnorrPublicKey()
    public_key = sch.import_public_key_hex(pubkey_from_file)

    data_to_sign = bytearray()
    for i in range(2,10):
        data_to_sign.append(rdcp[i]) # add static RDCP Header fields: Origin, SeqNr, Destination, MsgType, PayloadLength
    for i in range(0, num_bytes):
        data_to_sign.append(rdcp[16+i]) # add the first num_bytes of the RDCP Payload
    signature = bytearray()
    for i in range(0, 65):
        signature.append(rdcp[i + 16 + num_bytes])

    m = hashlib.sha256()
    m.update(data_to_sign)
    hashdigest = m.digest()

    hexstring1 = ''.join('{:02X}'.format(x) for x in signature[0:33])
    hexstring2 = ''.join('{:02X}'.format(x) for x in signature[33:])
    hexstring_of_signature = hexstring1 + ":" + hexstring2
    sig = sch.import_signature_hex(hexstring_of_signature)

    verification = False

    try:
        v = sch.verify(public_key, hashdigest, sig)
        verification = v
    except Exception as e:
        print("Schnorr Verify Error:", e)

    return verification


def pretty_print_rdcp(m, colorstring="normal"):
    """Pretty-print an RDCP message in a given color"""
    rdcp = craft_rdcp_from_message(m)
    rdcp_sender, rdcp_sender_info = rdcp_get_sender(rdcp)
    rdcp_origin, rdcp_origin_info = rdcp_get_origin(rdcp)
    rdcp_seqnr, rdcp_seqnr_decimal = rdcp_get_seqnr(rdcp)
    rdcp_destination, rdcp_destination_info = rdcp_get_destination(rdcp)
    rdcp_messagetype, rdcp_messagetype_readable = rdcp_get_messagetype(rdcp)
    rdcp_payloadlength, rdcp_payloadlength_decimal = rdcp_get_payloadlength(rdcp)
    rdcp_counter, rdcp_counter_decimal = rdcp_get_counter(rdcp)
    rdcp_relay1, rdcp_relay1_decimal = rdcp_get_relay1(rdcp)
    rdcp_relay2, rdcp_relay2_decimal = rdcp_get_relay2(rdcp)
    rdcp_relay3, rdcp_relay3_decimal = rdcp_get_relay3(rdcp)
    rdcp_crc16, rdcp_crc16_decimal = rdcp_get_crc16(rdcp)

    print(
        color[colorstring] + "RDCP Sender      :" + color["normal"],
        rdcp_sender + " (" + rdcp_sender_info + ")",
    )
    print(
        color[colorstring] + "RDCP Origin      :" + color["normal"],
        rdcp_origin + " (" + rdcp_origin_info + ")",
    )
    print(
        color[colorstring] + "RDCP Sequence Nr :" + color["normal"],
        rdcp_seqnr + " (" + str(rdcp_seqnr_decimal) + ")",
    )
    print(
        color[colorstring] + "RDCP Destination :" + color["normal"],
        rdcp_destination + " (" + rdcp_destination_info + ")",
    )
    print(
        color[colorstring] + "RDCP Message Type:" + color["normal"],
        rdcp_messagetype,
        "  (" + rdcp_messagetype_readable + ")",
    )
    print(
        color[colorstring] + "RDCP Payload Len :" + color["normal"],
        rdcp_payloadlength,
        "  (" + str(rdcp_payloadlength_decimal) + ")",
    )
    print(
        color[colorstring] + "RDCP TransmCount :" + color["normal"],
        rdcp_counter,
        "  (" + str(rdcp_counter_decimal) + ")",
    )

    relay, delay = get_relay_and_delay(rdcp_relay1_decimal)
    print(
        color[colorstring] + "RDCP Relay 1     :" + color["normal"],
        rdcp_relay1,
        "  (" + relay + ", " + delay + ")",
    )
    relay, delay = get_relay_and_delay(rdcp_relay2_decimal)
    print(
        color[colorstring] + "RDCP Relay 2     :" + color["normal"],
        rdcp_relay2,
        "  (" + relay + ", " + delay + ")",
    )
    relay, delay = get_relay_and_delay(rdcp_relay3_decimal)
    print(
        color[colorstring] + "RDCP Relay 3     :" + color["normal"],
        rdcp_relay3,
        "  (" + relay + ", " + delay + ")",
    )
    print(
        color[colorstring] + "RDCP CRC-16      :" + color["normal"], rdcp_crc16, end=" "
    )
    if verify_crc16(rdcp) == True:
        print(color["green"] + "(CRC OK)" + color["normal"])
    else:
        print(color["red"] + "(Bad CRC)" + color["normal"])
        return  # Do not print payload when checksum is bad

    try:
        if len(rdcp) > 16:
            if rdcp_messagetype == "0xFF":
                pass
            elif rdcp_messagetype == "0x0F": # ACK
                sigstatus = "(unsigned)"
                if rdcp_payloadlength_decimal > 3:
                    valid = getSchnorrVerification(rdcp, 3)
                    if valid == True:
                        sigstatus = "(signature OK)"
                    else:
                        sigstatus = "(signature BAD)"
                acktype = rdcp[18]
                confirmed = rdcp[16] + 256 * rdcp[17]
                print(color[colorstring] + "RDCP ACK property: " + color["normal"], end ="")
                print("RefNr", hex_quad(confirmed), "AckType", acktype, sigstatus)

            elif rdcp_messagetype == "0x0A": # TIMESTAMP
                sigstatus = "(unsigned)"
                if rdcp_payloadlength_decimal > 6:
                    valid = getSchnorrVerification(rdcp, 6)
                    if valid == True:
                        sigstatus = "(signature OK)"
                    else:
                        sigstatus = "(signature BAD)"
                year = rdcp[16]
                month = rdcp[17]
                day = rdcp[18]
                hour = rdcp[19]
                min = rdcp[20]
                status = rdcp[21]
                print(color[colorstring] + "RDCP TIMESTAMP   : " + color["normal"], end ="")
                print(str(day).zfill(2) + "." + str(month).zfill(2) + "." + str(year+2025) + " " + str(hour).zfill(2) + ":" + str(min).zfill(2) + " [RDCP Infrastructure Mode " + str(status) + "]", sigstatus)

            elif rdcp_messagetype == "0x1A": # CITIZEN REPORT
                aeskey = getSharedSecret(rdcp_origin)
                if aeskey == None:
                    print(color["red"] + "No key material available, cannot decrypt" + color["normal"])
                    return

                iv = bytearray()
                iv.append(rdcp[2])
                iv.append(rdcp[3])
                iv.append(rdcp[4])
                iv.append(rdcp[5])
                iv.append(rdcp[6])
                iv.append(rdcp[7])
                iv.append(rdcp[8])
                iv.append(rdcp[9])
                iv.append(0)
                iv.append(0)
                iv.append(0)
                iv.append(0)

                ad = iv[0:8]
                ciphertext = rdcp[16:]

                payload = bytearray()

                aesgcm = AESGCM(aeskey)
                try:
                    payload = aesgcm.decrypt(bytes(iv), bytes(ciphertext), bytes(ad))
                except:
                    print(color["red"] + "Authentication / decryption failed. Bad message or key material." + color["normal"])
                    return

                print(color[colorstring] + "RDCP CIRE Type   : " + color["normal"], end ="");
                subtype = payload[16-16]
                if (subtype == 0):
                    print("EMERGENCY")
                if (subtype == 1):
                    print("CITIZEN REQUEST")
                if (subtype == 2):
                    print("RESPONSE")
                refnr = 256 * int(payload[18-16]) + int(payload[17-16])
                print(color[colorstring] + "RDCP CIRE RefNr  : " + color["normal"], end ="");
                print(hex_quad(refnr))
                print(color[colorstring] + "RDCP CIRE Message: " + color["normal"], end ="");
                message = unishox2.decompress(bytes(payload[19-16:]), 512)
                print(message)
            elif rdcp_messagetype == "0x10":
                if rdcp_destination != "0xFFFF":
                    # encrypted, cannot display
                    pass
                else:
                    print(
                        color[colorstring] + "RDCP Off. Ann.   : " + color["normal"],
                        end="",
                    )
                    subtype = rdcp[16]
                    reference_number = 256 * int(rdcp[18]) + int(rdcp[17])
                    lifetime = 256 * int(rdcp[20]) + int(rdcp[19])
                    morefrag = rdcp[21]
                    if subtype == 0x22:
                        print(
                            "Message lifetime update for reference_number",
                            reference_number,
                            "to",
                            lifetime,
                        )
                    if (subtype == 0x10) or (subtype == 0x20):
                        print(
                            "New message with reference_number",
                            reference_number,
                            "and lifetime",
                            lifetime,
                            "with more_fragments",
                            morefrag,
                        )
                        udecoded = unishox2.decompress(bytes(rdcp[22:]), 512)
                        print(
                            color[colorstring] + "OA Content       :" + color["normal"],
                            udecoded,
                        )
            else:
                print(
                    color[colorstring] + "RDCP Payload hex : " + color["normal"], end=""
                )
                readable = ""
                for b in range(16, len(rdcp)):
                    hb = hex_duo(rdcp[b])[2:]
                    print(hb, end=" ")
                    v = int(rdcp[b])
                    if v > 31 and v < 127:
                        readable += "%c" % v
                    else:
                        readable += "."
                print(color["normal"])
                print(
                    color[colorstring]
                    + "RDCP Payload text: "
                    + color["normal"]
                    + readable
                    + color["normal"]
                )
    except Exception as e:
        print(color["red"] + "Payload printing failed" + color["normal"] + " (error: " + str(e) + ")")

    return


def rx_verbose(rxstring):
    """Pretty-print a received LoRa/RDCP packet given as LoRa modem RX line string"""
    global last_message
    regex = re.compile("^.*: RX (.*)")
    m = regex.match(rxstring)
    if m == None:
        if "SIMRX" in rxstring:
            return
        if "HELP" in rxstring:
            return
        print(color["red"] + "Not a valid RX line" + color["normal"])
        return
    base64msg = m.group(1)
    try:
        decoded = base64.b64decode(base64msg)
        last_message = base64msg
        last_message = last_message.replace("'", "")
    except:
        print(color["red"] + "Base64 decoding failed." + color["normal"])
        return
    length = len(decoded)
    if length < 16:
        print_hex_readable(decoded)
    if length < RDCP_HEADER_SIZE:
        print(
            color["red"]
            + "Not an RDCP message."
            + color["normal"]
            + " (shorter than RDCP header size)"
        )
        return
    pretty_print_rdcp(base64.b64decode(base64msg), "green")
    return


def tx_verbose(rxstring):
    """Pretty-print a sent LoRa/RDCP packet given as LoRa modem TX line string"""
    global last_message
    regex = re.compile("^.*: TX (.*)")
    m = regex.match(rxstring)
    if "wallclock" in rxstring:
        return
    if "TXQi" in rxstring:
        return
    if "HELP" in rxstring:
        return
        print(color["red"] + "Not a valid TX line" + color["normal"])
        return
    base64msg = m.group(1)
    try:
        decoded = base64.b64decode(base64msg)
        last_message = base64msg
        last_message = last_message.replace("'", "")
    except:
        print(color["red"] + "Base64 decoding failed." + color["normal"])
        return
    length = len(decoded)
    if length < 16:
        print_hex_readable(decoded)
    if length < RDCP_HEADER_SIZE:
        print(
            color["red"]
            + "Not an RDCP message."
            + color["normal"]
            + " (shorter than RDCP header size)"
        )
        return
    pretty_print_rdcp(base64.b64decode(base64msg), "cyan")
    return


if __name__ == "__main__":
    while True:
        line = ""
        try:
            line = input("> ")
        except:
            break
        if line == "stop" or line == "quit" or line == "exit":
            break
        if line.startswith("RX "):
            rx_verbose("INPUT: " + line)
        else:
            rx_verbose(line)

# EOF
