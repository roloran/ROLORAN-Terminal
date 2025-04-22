# ROLORAN-Terminal

Text-based Serial Terminal application for interaction with RDCP-capable LoRa devices

## Background

ROLORAN-Terminal is a text-based/line-oriented application to interact with LoRa devices over serial (UART, USB-CDC-ACM, ...) connections. It has been designed to simplify the management, testing, and debugging of RDCP-capable (ROLORAN Disaster Communication Protocol) LoRa devices and infrastructures. It is thus intended to be used by developers and RDCP infrastructure operators, not end-users. While any other serial terminal software could be used to interact with such LoRa devices, ROLORAN-Terminal provides useful shortcuts for typical RDCP DevOps tasks.

## Installing ROLORAN-Terminal

ROLORAN-Terminal is implemented in Python, so you need a working Python3 environment and some Python modules (pyserial, unishox2-py3, ecdsa; commonly used in RDCP-related tools) installed. Clone the repository and make `roloran-terminal.py` executable.

For macOS users, a PIP-installable wheel is provided for py3-unishox2 as we faced memory management issues with certain C compilers and newer macOS versions.

## Running ROLORAN-Terminal

As a text-based application, ROLORAN-Terminal should be started on the command line in a terminal emulator (e.g., Ghostty, WezTerm, Kitty, ...) or multiplexer (e.g., zellij, tmux, screen) of your choice.

Before running `roloran-terminal.py`, the environment variable `LORADEV` should be set to the device name of the LoRa device to interact with, for example `/dev/ttyACM0` or `/dev/cu.usbmodem11101`. Note: This is usually the same device name you upload your ROLORAN LoRa device firmware to. If `LORADEV` is not set, ROLORAN-Terminal tries to suggest commonly named `/dev` entries existing on your system and you can pick one interactively.

Multiple instances of ROLORAN-Terminal can be used in parallel as long as they interact with different LoRa devices. If multiple instances communicate with the same LoRa device, behavior is unspecified.

## Using ROLORAN-Terminal

ROLORAN-Terminal starts in `interactive` mode.

While ROLORAN-Terminal runs, data (lines of text) received from the LoRa device are printed on the screen. You can use your terminal emulator's or multiplexer's scrollback buffer as usual.

You can enter commands at the prompt in the last line of ROLORAN-Terminal's output. Input is handled by the readline library in a separate thread, and input will only be evaluated after pressing the Enter/Return key. A history of the command input is saved on quit, so you can use the "cursor/arrow up" key to select and repeat previous commands, even across sessions.

Enter either of `stop`, `exit` or `quit` at the prompt to end ROLORAN-Terminal gracefully. You can ^C your way out of it as well, e.g., if you hit an uncaught exception.

Please note that all ROLORAN-Terminal commands should be entered in all-lowercase letters.

Timestamping and moderate syntax highlighting is applied to text received from typical ROLORAN / RDCP LoRa device firmware implementations. Received RDCP messages (as identified by "RX" lines) are dissected and the RDCP header (as well as sometimes the RDCP payload) are pretty-printed. This was the original purpose of previous ROLORAN-Terminal versions and has been updated to RDCP v0.4. Received data is also recorded in a device-name-specific logfile. You can adjust the command history and logfile behavior and used filenames near the top of `roloran-terminal.py` if the defaults do not match your preferences.

ROLORAN-Terminal can be used in `interactive` and `craft` mode; additionally, text files with commands can be fed to it in the background. These three operations are described in the following sections.

### Interactive mode

While in interactive mode, the input prompt text is shown in 'cyan' (the actual color depends on the used terminal color theme on your machine).

Text lines entered in interactive mode are sent to the LoRa device; thus, this mode can be used to configure, manage, and otherwise interact with the connected device just like with any other serial terminal software. This mode will typically be used most of the time.

Obviously, the three commands to end ROLORAN-Terminal mentioned above will not be sent to the LoRa device. Additionally, the command `craft` is used to enter the new craft mode.

### Craft mode

The craft mode is the latest addition to ROLORAN-Terminal. It can be used to manually construct arbitrary RDCP v0.4 messages, which then can be transmitted or simulated to be received by the LoRa device.

In craft mode, the input prompt text is shown in 'magenta'. You can switch back to the interactive mode using the command `interactive`.

The following commands can currently be used in craft mode:

- `clear` resets the crafted RDCP message to one with an all-zero RDCP header and no RDCP payload. Note that this RDCP message has an invalid CRC-16 checksum. The other commands that manipulate the RDCP header or RDCP payload update the checksum appropriately.
- `sender` changes the sender RDCP address in the RDCP header. New addresses must be given as 4-digit hexadecimal numbers. Example: `sender AF00`
- `origin` changes the origin RDCP address in the RDCP header.
- `destination` changes the destination RDCP address in the RDCP header.
- `seq` changes the sequence number in the RDCP header. The new sequence number can be given as hexadecimal or decimal number. Examples: `seq 0x001F`, `seq 15`
- `type` changes the RDCP message type in the RDCP header. The new message type can either be given as hexadecimal number or substring. Examples: `type 0x10`, `type ack`, `type cire`, `type emer`, `type ping`
- `length` changes the payload length value in the RDCP header. This does not have to be used manually when using the payload commands below, but can be used to craft intentionally malformed RDCP messages. Supports hexadecimal or decimal numbers.
- `count` changes the retransmission counter in the RDCP header. Supports hexadecimal and decimal numbers.
- `relay1`, `relay2` and `relay3` set the relay/delay 8-bit fields in the RDCP header. The parameter must be a 2-digit hexadecimal number. Remember that the first hex digit is the relay identifier and the second hex digit is the delay/timeslot assignment. Example: `relay1 25`
- `crc` updates the checksum field in the RDCP header. When called without parameter, the proper CRC-16 (CCITT) checksum is calculated and set. Give a 4-digit hexadecimal number as parameter to set an arbitrary value.
- `payload` can be used to set an arbitrary RDCP payload. The payload length RDCP header field is updated automatically. Examples:
  - `payload text Hello world` sets the payload to the given plain text. Plain text is used, for example, in RDCP TEST messages.
  - `payload unishox2 Hello world` sets the payload to the Unishox2-compressed data of the given plain text. Unishox2-compressed text is used, for example, in RDCP EMERGENCY messages.
  - `payload hex 12AF34DE` sets a 4-byte payload with values 0x12, 0xAF, 0x34 and 0xDE.
  - `payload base64 SGVsbG8gd29ybGQ=` sets the payload to whatever results from decoding the given Base64-encoded data.
- `print` or `show` simply pretty-print the crafted RDCP message on the screen again. Useful if you meanwhile received a lot of data from your LoRa device.
- `tx` and `simrx` send the crafted RDCP message as `TX` or `SIMRX` line to your connected LoRa device. These are the usual operations once the RDCP message has been crafted completely.
- `save` and `load` can be used to save and load crafted RDCP messages for later use. They expect a name as parameter. Examples: `save ping-0200`, `load oa-test-01`
- `parse` expects a Base64-encoded RDCP message as parameter, which is then used as the crafted RDCP message. Can be used, for example, to fiddle with received/copy&pasted RDCP messages.
- `uselast` uses the last received RDCP message as crafted RDCP message. This only works if a valid `RX` line was already received in the current ROLORAN-Terminal session. It simply is a shortcut for `parse` without having to copy&paste the most recently received RDCP message manually.

Please feel free to add further commands to craft mode to make it a more interactive replacement for our RDCP packet crafter. Also, craft mode does not handle wrong input and other errors well yet. Please feel free to improve.

### Feeding text files with commands

In a third thread (besides the ones for serial communication and keyboard input handling), ROLORAN-Terminal watches the file system for new text files with a `.rterm` suffix. When such a file is detected, its content is sent line-by-line to the LoRa device; afterwards, the file is renamed to `filename.rterm.done`. There is a 1 second delay between each line sent to the LoRa device (adjust `script_line_delay` in `roloran-terminal.py` if required).

This can be used to inject arbitrary commands for the LoRa device independent of keyboard input in interactive mode. This may be useful when such commands are generated by other scripts, or if you want to store sequences of commands in a text file instead of repeating them from history line-by-line.

## Limitations

ROLORAN-Terminal currently does not handle encrypted RDCP payloads and does not support cryptographic signatures (in RDCP payloads or 0x30 type messages) yet, neither for pretty-printing nor in craft mode. Please contribute. :-)
