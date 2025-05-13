"""
Modified Bleak example taken from https://github.com/hbldh/bleak
(c) David Lechner, MIT License

Adapted to connect by device name and use Send/Receive interface functions.
"""

import asyncio
import sys
from itertools import count, takewhile
from typing import Iterator
from time import sleep

from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

UART_SERVICE_UUID = "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
UART_RX_CHAR_UUID = "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"
UART_TX_CHAR_UUID = "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"


def sliced(data: bytes, n: int) -> Iterator[bytes]:
    return takewhile(len, (data[i : i + n] for i in count(0, n)))


devicename = "RDCP-MG-AEFF"
ble_rx_content = []
ble_has_tx = False
ble_tx_content = ""


def ble_set_devicename(n):
    global devicename
    devicename = n
    return


def ble_start():
    asyncio.run(uart_terminal())
    return


def ble_rx_available():
    global ble_rx_content
    result = False
    if len(ble_rx_content) > 0:
        result = True
    return result


def ble_rx_get():
    global ble_rx_content
    result = ""
    if len(ble_rx_content) > 0:
        result = ble_rx_content.pop(0)
        result = result.strip()
        result += "\n"
        if len(result) < 2:
            result = ""
    return result


def ble_tx(s):
    global ble_tx_content, ble_has_tx
    ble_tx_content += s
    ble_has_tx = True
    return


async def uart_terminal():
    global devicename
    device = await BleakScanner.find_device_by_name(devicename)

    if device is None:
        print("BLE ERROR: BLE device", devicename, "not found. Aborting.")
        sys.exit(1)


    def handle_disconnect(_: BleakClient):
        global devicename
        print("BLE ERROR: Device", devicename, "was disconnected.")
        for task in asyncio.all_tasks():
            task.cancel()
        sys.exit(2)


    def handle_rx(_: BleakGATTCharacteristic, data: bytearray):
        global ble_rx_content
        s = ""
        try:
            s = data.decode("utf-8")
        except:
            pass
        if len(s) > 0:
            # print("BLE INFO: Received ->", s, end="")
            ble_rx_content.append(s)


    def blocking_io():
        with open('/dev/urandom', 'rb') as f:
            return f.read(1)


    async with BleakClient(device, disconnected_callback=handle_disconnect) as client:
        await client.start_notify(UART_TX_CHAR_UUID, handle_rx)

        print("BLE INFO: Device", devicename, "connected")

        loop = asyncio.get_running_loop()
        nus = client.services.get_service(UART_SERVICE_UUID)
        rx_char = nus.get_characteristic(UART_RX_CHAR_UUID)

        global ble_tx_content
        global ble_has_tx

        while True:
            random_garbage = await loop.run_in_executor(None, blocking_io)
            sleep(0.1)

            if not ble_has_tx:
                continue

            data = bytearray()
            if ble_has_tx:
                for c in ble_tx_content:
                    data.append(ord(c))
                ble_tx_content = ""
                ble_has_tx = False

            for s in sliced(bytes(data), rx_char.max_write_without_response_size):
                await client.write_gatt_char(rx_char, s, response=False)

            s = ""
            try:
                s = data.decode("utf-8")
            except:
                pass

            # print("BLE INFO: Sent ->", s, end="")


if __name__ == "__main__":
    try:
        asyncio.run(uart_terminal())
    except asyncio.CancelledError:
        pass

# EOF
