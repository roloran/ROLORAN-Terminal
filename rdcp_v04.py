#!/usr/bin/env python3

"""
Simple RDCP v0.4 packet crafter for Python3

Intended for creating test messages when developing on T-Deck with Serial commands.
Could be extended into a more generic RDCP module for Python3 scripts.
"""

# We need Base64 encoding for Serial communication with a LoRa modem
# and unishox2 for compressing natural language text strings.
import base64
import unishox2

# Modules for symmetric encryption, hashing, and Schnorr signatures
from cryptography.exceptions import InvalidKey, InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import schnorr
import hashlib

# We store some information in global variables but make them adjustable via provided functions.
rdcp_my_address = (
    0xAD00  # Our own device's RDCP address. Mostly used as Origin and Sender.
)
rdcp_sequence_number = (
    0  # RDCP sequence number to use. Must be increased for each RDCP message.
)
rdcp_oa_reference_number = 0  # RDCP Official Announcement reference number to use. Must be increased for each Official Announcement.


# We define "constants" for the RDCP message types and subtypes in use
RDCP_MSGTYPE_TEST = 0x00
RDCP_MSGTYPE_ECHO_REQUEST = 0x01
RDCP_MSGTYPE_ECHO_RESPONSE = 0x02
RDCP_MSGTYPE_BBK_STATUS_REQUEST = 0x03
RDCP_MSGTYPE_BBK_STATUS_RESPONSE = 0x04
RDCP_MSGTYPE_DA_STATUS_REQUEST = 0x05
RDCP_MSGTYPE_DA_STATUS_RESPONSE = 0x06
RDCP_MSGTYPE_TRACEROUTE_REQUEST = 0x07
RDCP_MSGTYPE_TRACEROUTE_RESPONSE = 0x08
RDCP_MSGTYPE_BLOCK_DEVICE_ALERT = 0x09
RDCP_MSGTYPE_TIMESTAMP = 0x0A
RDCP_MSGTYPE_DEVICE_RESET = 0x0B
RDCP_MSGTYPE_DEVICE_REBOOT = 0x0C
RDCP_MSGTYPE_DEVICE_MAINTENANCE = 0x0D
RDCP_MSGTYPE_RESET_INFRASTRUCTURE = 0x0E
RDCP_MSGTYPE_ACK = 0x0F
RDCP_MSGTYPE_OFFICIAL_ANNOUNCEMENT = 0x10
RDCP_MSGTYPE_RESET_ALL_ANNOUNCEMENTS = 0x11
RDCP_MSGTYPE_CITIZEN_REPORT = 0x1A
RDCP_MSGTYPE_PRIVILEGED_REPORT = 0x1C
RDCP_MSGTYPE_FETCH_ALL_NEW_MESSAGES = 0x20
RDCP_MSGTYPE_FETCH_MESSAGE = 0x21
RDCP_MSGTYPE_DELIVERY_RECEIPT = 0x2A
RDCP_MSGTYPE_SCHEDULE_RCPT = 0x2B
RDCP_MSGTYPE_SIGNATURE = 0x30
RDCP_MSGTYPE_HEARTBEAT = 0x31
RDCP_MSGTYPE_RTC = 0x32

RDCP_MSGTYPE_OA_SUBTYPE_RESERVED = 0x00
RDCP_MSGTYPE_OA_SUBTYPE_NONCRISIS = 0x10
RDCP_MSGTYPE_OA_SUBTYPE_CRISIS_TXT = 0x20
RDCP_MSGTYPE_OA_SUBTYPE_CRISIS_GFX = 0x21
RDCP_MSGTYPE_OA_SUBTYPE_UPDATE = 0x22
RDCP_MSGTYPE_OA_SUBTYPE_FEEDBACK = 0x30
RDCP_MSGTYPE_OA_SUBTYPE_INQUIRY = 0x31


def rdcp_set_my_rdcp_address(new_address):
    """change this device's RDCP address"""
    global rdcp_my_address
    rdcp_my_address = new_address
    return rdcp_my_address


def rdcp_next_sequence_number():
    """create a new RDCP sequence number"""
    global rdcp_sequence_number
    rdcp_sequence_number += 1
    return rdcp_sequence_number


def rdcp_set_sequence_number(seqnr):
    """set the last used RDCP sequence number (if persisted elsewhere)"""
    global rdcp_sequence_number
    rdcp_sequence_number = seqnr
    return rdcp_sequence_number


def rdcp_get_sequence_number():
    """get the last used RDCP sequence number (to persist somewhere else)"""
    global rdcp_sequence_number
    return rdcp_sequence_number


def rdcp_next_oa_reference_number():
    """create a new RDCP Official Announcement reference number"""
    global rdcp_oa_reference_number
    rdcp_oa_reference_number += 1
    return rdcp_oa_reference_number


def rdcp_set_oa_reference_number(refnr):
    """set the last used RDCP OA reference number (if persisted somewhere else)"""
    global rdcp_oa_reference_number
    rdcp_oa_reference_number = refnr
    return rdcp_oa_reference_number


def rdcp_get_oa_reference_number():
    """get the last used RDCP OA reference number (to persist elsewhere)"""
    global rdcp_oa_reference_number
    return rdcp_oa_reference_number


def crc16(data):
    """calculate CRC-16 (CCITT) checksum"""
    lookup = [
        0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7, 0x8108,
        0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF, 0x1231, 0x0210,
        0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6, 0x9339, 0x8318, 0xB37B,
        0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE, 0x2462, 0x3443, 0x0420, 0x1401,
        0x64E6, 0x74C7, 0x44A4, 0x5485, 0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE,
        0xF5CF, 0xC5AC, 0xD58D, 0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6,
        0x5695, 0x46B4, 0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D,
        0xC7BC, 0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
        0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B, 0x5AF5,
        0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12, 0xDBFD, 0xCBDC,
        0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A, 0x6CA6, 0x7C87, 0x4CE4,
        0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41, 0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD,
        0xAD2A, 0xBD0B, 0x8D68, 0x9D49, 0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13,
        0x2E32, 0x1E51, 0x0E70, 0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A,
        0x9F59, 0x8F78, 0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E,
        0xE16F, 0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
        0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E, 0x02B1,
        0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256, 0xB5EA, 0xA5CB,
        0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D, 0x34E2, 0x24C3, 0x14A0,
        0x0481, 0x7466, 0x6447, 0x5424, 0x4405, 0xA7DB, 0xB7FA, 0x8799, 0x97B8,
        0xE75F, 0xF77E, 0xC71D, 0xD73C, 0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657,
        0x7676, 0x4615, 0x5634, 0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9,
        0xB98A, 0xA9AB, 0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882,
        0x28A3, 0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
        0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92, 0xFD2E,
        0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9, 0x7C26, 0x6C07,
        0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1, 0xEF1F, 0xFF3E, 0xCF5D,
        0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8, 0x6E17, 0x7E36, 0x4E55, 0x5E74,
        0x2E93, 0x3EB2, 0x0ED1, 0x1EF0,
    ]
    crc = 0xFFFF
    for i in range(0, len(data)):
        b = data[i]
        crc = (crc << 8) ^ lookup[(crc >> 8) ^ b]
        crc &= 0xFFFF
    return crc


def rdcp_create_message(
    sender=rdcp_my_address,  # we are the sender by default
    origin=rdcp_my_address,  # we are the origin by default
    sequence_number=-1,  # get a new sequence_number if none given
    destination=0xFFFF,  # broadcast destination by default
    message_type=RDCP_MSGTYPE_TEST,  # test message by default
    counter=0x00,  # retransmission counter
    relay1=0xE0,  # relay/delay 1
    relay2=0xE0,  # relay/delay 2
    relay3=0xE0,  # relay/delay 3
    crc=0x0000,  # CRC-16
    payload=b"",
    add_tag_length = 0 # add this value to payload length in case we got an AES-GCM tag
):
    """craft an RDCP message with header and given payload"""
    # the payload as bytearray
    # Start with an empty byte array
    rdcp_msg = bytearray()

    if sequence_number == -1:
        sequence_number = rdcp_next_sequence_number()

    # prepare the header
    rdcp_msg.append(sender % 256)  # lower byte comes first
    rdcp_msg.append(sender // 256)  # higher byte comes second
    rdcp_msg.append(origin % 256)
    rdcp_msg.append(origin // 256)
    rdcp_msg.append(sequence_number % 256)
    rdcp_msg.append(sequence_number // 256)
    rdcp_msg.append(destination % 256)
    rdcp_msg.append(destination // 256)
    rdcp_msg.append(message_type)
    rdcp_msg.append(
        (len(payload) + add_tag_length) % 256
    )  # avoid too long payloads. We make sure here it fits into 1 byte.
    rdcp_msg.append(
        counter % 256
    )  # fit into 1 byte if someone created a too large counter
    rdcp_msg.append(
        relay1 % 256
    )  # fit into 1 byte if someone created a too large value
    rdcp_msg.append(
        relay2 % 256
    )  # fit into 1 byte if someone created a too large value
    rdcp_msg.append(
        relay3 % 256
    )  # fit into 1 byte if someone created a too large value

    data_for_crc = bytearray()
    data_for_crc.extend(rdcp_msg)
    data_for_crc.extend(payload)
    crc = crc16(data_for_crc)
    rdcp_msg.append(crc % 256)
    rdcp_msg.append(crc // 256)

    # append the payload
    rdcp_msg.extend(payload)

    return rdcp_msg


def rdcp_message_as_hexstring(rdcp_msg, sep=" "):
    """convert an RDCP message into a string of hex bytes"""
    result = ""
    for byte in rdcp_msg:
        converted = str(hex(byte)[2:]).upper()
        if len(converted) < 2:
            result += (
                "0"  # add a leading zero if the value fits into a single hex digit
            )
        result += converted + sep
    return result.rstrip()


def rdcp_message_as_base64(rdcp_msg):
    """convert an RDCP message into a Base64-encoded bytearray"""
    return base64.b64encode(rdcp_msg)


def rdcp_message_pretty_print(m):
    """Pretty-print a crafted RDCP message"""
    print("---")
    print("RDCP message as hexdump:", rdcp_message_as_hexstring(m), "- length", len(m))
    print("RDCP message in Base64 :", str(rdcp_message_as_base64(m))[2:-1])
    print()
    print("To use this message with a LoRa Modem, try either of:")
    print("TX", str(rdcp_message_as_base64(m))[2:-1])
    print("SIMRX", str(rdcp_message_as_base64(m))[2:-1], "\n\n")
    return


def rdcp_create_OA_payload(
    subtype=RDCP_MSGTYPE_OA_SUBTYPE_NONCRISIS,
    reference_number=-1,
    lifetime=60366,  # 366 days, magic number according to RDCP spec
    more_fragments=0,  # we don't use fragments by default
    text="",
):
    """Create the payload for an Official Announcement of subtype 0x10 or 0x20
    Not to be used for message lifetime updates (see below)."""
    # Official announcement as plain text (not compressed yet)
    payload = bytearray()

    if reference_number == -1:
        reference_number = rdcp_next_oa_reference_number()

    # First, fill the subheader
    payload.append(subtype)
    payload.append(reference_number % 256)
    payload.append(reference_number // 256)
    payload.append(lifetime % 256)
    payload.append(lifetime // 256)
    payload.append(more_fragments)

    # Then, add the message text itself, but Unishox2-compressed
    compressed_text, original_size = unishox2.compress(text)
    payload.extend(compressed_text)

    return payload


def rdcp_create_OA_update_payload(reference_number, lifetime):
    """Create the payload for an Official Announcement of subtype 0x22 for updating an
    existing message's lifetime."""
    payload = bytearray()

    payload.append(RDCP_MSGTYPE_OA_SUBTYPE_UPDATE)
    payload.append(reference_number % 256)
    payload.append(reference_number // 256)
    payload.append(lifetime % 256)
    payload.append(lifetime // 256)
    payload.append(0)  # "more fragments" not relevant here, even once we use fragments

    return payload


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


def hash_and_schnorr(data):
    sch = schnorr.SchnorrSignature()
    pubkey_from_file = getSchnorrPublicKey()
    public_key = sch.import_public_key_hex(pubkey_from_file)
    privkey_from_file = getSchnorrPrivateKey()
    private_key = sch.import_private_key_hex(privkey_from_file)

    m = hashlib.sha256()
    m.update(data)
    hashdigest = m.digest()
    hexhash = ''.join('{:02X}'.format(x) for x in hashdigest)
    print("Hash for Schnorr signature:", hexhash)

    signature = sch.sign(private_key, hashdigest)

    R, s = signature
    R_bytes = R.to_bytes(encoding='compressed')
    s_bytes = s.to_bytes(32, 'big')

    hexstring1 = ''.join('{:02X}'.format(x) for x in R_bytes)
    hexstring2 = ''.join('{:02X}'.format(x) for x in s_bytes)
    hexstring_of_signature = hexstring1 + ":" + hexstring2
    print("Schnorr signature in hex:", hexstring_of_signature)

    result = bytearray()
    result.extend(R_bytes)
    result.extend(s_bytes)

    return result

def bytearray_to_string(b, sep=" "):
    hexdata = sep.join('{:02X}'.format(x) for x in b)
    return hexdata

def craft_oa_pub(oatext, subtype, fragment_size=162, lifetime=10):
    """Craft one or more public/broadcast OA fragments and the signature message"""
    compressed_text, original_size = unishox2.compress(oatext)
    l = len(compressed_text)

    reference_number = rdcp_next_oa_reference_number() # single RefNr for all fragments
    schnorrdata = bytearray()

    if l > fragment_size: # oatext must be split into multiple fragments
      num_oas = 1 + (len(oatext) // fragment_size) # split the content, not its Unishox2 representation to enable decoding of fragments
      for oa_num in range(0, num_oas):
          payload = bytearray()
          payload.append(subtype)
          payload.append(reference_number % 256)
          payload.append(reference_number // 256)
          payload.append(lifetime % 256)
          payload.append(lifetime // 256)
          morefrags = num_oas - oa_num - 1
          payload.append(morefrags % 256)

          payload_slice_to_end = oatext[oa_num * fragment_size :]
          if morefrags > 0:
              compressed_text, original_size = unishox2.compress(payload_slice_to_end[0 : fragment_size+1])
          else:
              compressed_text, original_size = unishox2.compress(payload_slice_to_end)
          payload.extend(compressed_text)

          rm = rdcp_create_message(sender=0x0010, origin=0x0010, payload=payload, counter=4, message_type=RDCP_MSGTYPE_OFFICIAL_ANNOUNCEMENT)
          print("More fragments:", morefrags, str(rdcp_message_as_base64(rm))[2:-1])

          if oa_num == 0: # Header fields of the first fragment to be included in the Schnorr signature
              schnorrdata.append(0x0010 % 256) # origin
              schnorrdata.append(0x0010 // 256)
              schnorrdata.append(0xFFFF % 256) # destination
              schnorrdata.append(0xFFFF // 256)
              schnorrdata.append(RDCP_MSGTYPE_OFFICIAL_ANNOUNCEMENT % 256)
              schnorrdata.append(subtype % 256)
              schnorrdata.append(reference_number % 256)
              schnorrdata.append(reference_number // 256)
              schnorrdata.append(lifetime % 256)
              schnorrdata.append(lifetime // 256)
              schnorrdata.append(morefrags % 256)
          schnorrdata.extend(compressed_text) # append each fragment's Unishox2-compressed Content

    else: # compressed text fits into a single fragment
      payload = bytearray()
      payload.append(subtype)
      payload.append(reference_number % 256)
      payload.append(reference_number // 256)
      payload.append(lifetime % 256)
      payload.append(lifetime // 256)
      morefrags = 0
      payload.append(morefrags % 256)

      payload_slice_to_end = oatext[:]
      compressed_text, original_size = unishox2.compress(payload_slice_to_end)
      payload.extend(compressed_text)

      rm = rdcp_create_message(sender=0x0010, origin=0x0010, payload=payload, counter=4, message_type=RDCP_MSGTYPE_OFFICIAL_ANNOUNCEMENT)
      print("Single fragment:", str(rdcp_message_as_base64(rm))[2:-1])

      schnorrdata.append(0x0010 % 256) # origin
      schnorrdata.append(0x0010 // 256)
      schnorrdata.append(0xFFFF % 256) # destination
      schnorrdata.append(0xFFFF // 256)
      schnorrdata.append(RDCP_MSGTYPE_OFFICIAL_ANNOUNCEMENT % 256)
      schnorrdata.append(subtype % 256)
      schnorrdata.append(reference_number % 256)
      schnorrdata.append(reference_number // 256)
      schnorrdata.append(lifetime % 256)
      schnorrdata.append(lifetime // 256)
      schnorrdata.append(morefrags % 256)
      schnorrdata.extend(compressed_text) # append each fragment's Unishox2-compressed Content

    # calculate SHA-256 hash and Schnorr Signature, create Signature message
    sig = hash_and_schnorr(schnorrdata)
    payload = bytearray()
    payload.append(reference_number % 256)
    payload.append(reference_number // 256)
    payload.extend(sig)
    rm = rdcp_create_message(sender=0x0010, origin=0x0010, payload=payload, counter=4, message_type=RDCP_MSGTYPE_SIGNATURE)
    print("RDCP Signature message:", str(rdcp_message_as_base64(rm))[2:-1], end="\n\n")
    return


def craft_oa_priv(oatext, subtype, dest=0xAEFF, refnr=-1, lifetime=10):
    """Craft a private OA with AEAD"""
    compressed_text, original_size = unishox2.compress(oatext)
    l = len(compressed_text)
    if l > 162:
        print("ERROR: Non-public OA exceeds 162 bytes Unishox2-compressed content")
        return
    else:
        print("Private OA Content length:", len(oatext), "plain,", l, "compressed")

    if (refnr == -1):
        refnr = rdcp_next_oa_reference_number()

    schnorrdata = bytearray()

    payload = bytearray()
    payload.append(subtype)
    payload.append(refnr % 256)
    payload.append(refnr // 256)
    payload.append(lifetime % 256)
    payload.append(lifetime // 256)
    morefrags = 0
    payload.append(morefrags % 256)
    payload.extend(compressed_text)

    plain_rm = rdcp_create_message(sender=0x0010, origin=0x0010, destination=dest, payload=payload, counter=4, message_type=RDCP_MSGTYPE_OFFICIAL_ANNOUNCEMENT, add_tag_length=16)

    from rdcpcodec import getSharedSecret, hex_quad

    aeskey = getSharedSecret(hex_quad(dest))
    if aeskey == None:
        print("No key material available, cannot encrypt")
        return

    iv = bytearray()
    iv.append(plain_rm[2])
    iv.append(plain_rm[3])
    iv.append(plain_rm[4])
    iv.append(plain_rm[5])
    iv.append(plain_rm[6])
    iv.append(plain_rm[7])
    iv.append(plain_rm[8])
    iv.append(plain_rm[9])
    iv.append(0)
    iv.append(0)
    iv.append(0)
    iv.append(0)

    ad = iv[0:8] # additional data
    plaintext = plain_rm[16:]

    print("IV:", bytearray_to_string(iv), ", AD:", bytearray_to_string(ad));

    encrypted_payload = bytearray()

    aesgcm = AESGCM(aeskey)
    try:
        encrypted_payload = aesgcm.encrypt(iv, plaintext, ad)
    except:
        print("Authenticated encryption failed. Bad message or key material.")
        return

    print("Ciphertext + Tag:", bytearray_to_string(encrypted_payload));

    rm = bytearray()
    rm.extend(plain_rm[0:16])
    rm.extend(encrypted_payload)

    pl = len(encrypted_payload)
    rm[9] = pl % 256; # Update payload length RDCP Header field

    # Update CRC
    data_for_crc = bytearray()
    data_for_crc.extend(rm[0:14])
    data_for_crc.extend(rm[16:])
    crc = crc16(data_for_crc)
    rm[14] = crc % 256
    rm[15] = crc // 256

    print("Private OA:", str(rdcp_message_as_base64(rm))[2:-1], end="\n\n")
    return


def rdcp_create_message_inlinesig(
    sender=rdcp_my_address,  # we are the sender by default
    origin=rdcp_my_address,  # we are the origin by default
    sequence_number=-1,  # get a new sequence_number if none given
    destination=0xFFFF,  # broadcast destination by default
    message_type=RDCP_MSGTYPE_TEST,  # test message by default
    counter=0x00,  # retransmission counter
    relay1=0x00,  # relay/delay 1
    relay2=0xEE,  # relay/delay 2
    relay3=0xEE,  # relay/delay 3
    crc=0x0000,  # CRC-16
    payload=b"",
    add_tag_length = 0 # add this value to payload length in case we got an AES-GCM tag
):
    """craft an RDCP message with header and given payload as well as inline Schnorr signature"""
    rdcp_msg = bytearray()

    if sequence_number == -1:
        sequence_number = rdcp_next_sequence_number()

    # prepare the header
    rdcp_msg.append(sender % 256)  # lower byte comes first
    rdcp_msg.append(sender // 256)  # higher byte comes second
    rdcp_msg.append(origin % 256)
    rdcp_msg.append(origin // 256)
    rdcp_msg.append(sequence_number % 256)
    rdcp_msg.append(sequence_number // 256)
    rdcp_msg.append(destination % 256)
    rdcp_msg.append(destination // 256)
    rdcp_msg.append(message_type)
    rdcp_msg.append(
        (len(payload) + 65 + add_tag_length) % 256
    )  # avoid too long payloads. We make sure here it fits into 1 byte.
    rdcp_msg.append(
        counter % 256
    )  # fit into 1 byte if someone created a too large counter
    rdcp_msg.append(
        relay1 % 256
    )  # fit into 1 byte if someone created a too large value
    rdcp_msg.append(
        relay2 % 256
    )  # fit into 1 byte if someone created a too large value
    rdcp_msg.append(
        relay3 % 256
    )  # fit into 1 byte if someone created a too large value

    schnorrdata = bytearray()
    schnorrdata.extend(rdcp_msg[2:4]) # origin
    schnorrdata.extend(rdcp_msg[4:6]) # seqnr
    schnorrdata.extend(rdcp_msg[6:8]) # dest
    schnorrdata.extend(rdcp_msg[8:10]) # msgtype, payload length
    schnorrdata.extend(payload)
    sig = hash_and_schnorr(schnorrdata)
    payload.extend(sig)

    data_for_crc = bytearray()
    data_for_crc.extend(rdcp_msg)
    data_for_crc.extend(payload)
    crc = crc16(data_for_crc)
    rdcp_msg.append(crc % 256)
    rdcp_msg.append(crc // 256)

    # append the payload
    rdcp_msg.extend(payload)

    return rdcp_msg


def craft_rtc(rtc="20250421T085527Z", alarm=0, reset=0, persist=0):
    rtc_payload = bytearray()
    rtc_payload.append(alarm)
    rtc_payload.append(reset)
    rtc_payload.append(persist)
    for c in rtc:
        rtc_payload.append(ord(c))

    rm = rdcp_create_message_inlinesig(message_type=RDCP_MSGTYPE_RTC, destination=0x0200, payload=rtc_payload)
    print("RTC:", str(rdcp_message_as_base64(rm))[2:-1], end="\n\n")
    return


# ============
# main program
# ============

if __name__ == "__main__":
    print("RDCP Packet Crafter v0.4")

    # Test with a "Hello world" RDCPTEST message
    m = rdcp_create_message(payload=b"Hello world")
    rdcp_message_pretty_print(m)

    # Test with an official announcement
    payload = rdcp_create_OA_payload(
        text="08. August 2024, 11:55#Kuratorinnenführung mit Franziska Straubinger am 21.09.2024 um 14:00 Uhr im Museum Liaunig"
    )
    m = rdcp_create_message(
        message_type=RDCP_MSGTYPE_OFFICIAL_ANNOUNCEMENT, payload=payload
    )
    rdcp_message_pretty_print(m)

    # Test with a message lifetime update for the official announcement
    payload = rdcp_create_OA_update_payload(rdcp_get_oa_reference_number(), 5)
    m = rdcp_create_message(
        message_type=RDCP_MSGTYPE_OFFICIAL_ANNOUNCEMENT, payload=payload
    )
    rdcp_message_pretty_print(m)

    print("Ping 0x0100")
    m = rdcp_create_message(destination=0x0100, message_type=RDCP_MSGTYPE_ECHO_REQUEST)
    rdcp_message_pretty_print(m)

    print("Public official announcement (long)")
    craft_oa_pub("Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea re",
        RDCP_MSGTYPE_OA_SUBTYPE_CRISIS_TXT)

    print("Public official announcement (short)")
    craft_oa_pub("Hello world!", RDCP_MSGTYPE_OA_SUBTYPE_NONCRISIS)

    print("Private official announcement")
    craft_oa_priv("Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam volu", RDCP_MSGTYPE_OA_SUBTYPE_INQUIRY)

    print("RTC")
    craft_rtc("20250421T085527Z", 0, 0, 0)

# EOF
