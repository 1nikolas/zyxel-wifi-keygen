# zyxel-wifi-keygen
VMG1312-B10A default Wi-Fi password generator

## About VMG1312-B10A
This router was released in 2013 and is the only Zyxel router I could find that uses the VDSL MAC as a seed for the default Wi-Fi password.

Zyxel routers bind MAC Addresses like this:
| Mac Address           | Example           |
|-----------------------|-------------------|
| Modem MAC (VDSL)      | FF:FF:FF:FF:FF:00 |
| Wi-Fi 2.5G MAC        | FF:FF:FF:FF:FF:01 |
| Wi-Fi 5G MAC (if any) | FF:FF:FF:FF:FF:02 |
| LAN 1 MAC             | FF:FF:FF:FF:FF:03 |
| LAN 2 MAC             | FF:FF:FF:FF:FF:04 |
| ...                   | ...               |

So by knowing the Wi-Fi MAC Address, we know the VDSL (modem) MAC.

Models like VMG1312-B10D (2015) or even VMG8623-T50B (2020) use more or less the same algorithm but use the serial number as a seed (which is not known by just scanning the Wi-Fi).


## Files
### C_code
This folder contains the generator function code reverse engineered by Ghidra. Minimal edits were made to make it run on MacOS. The function is called `wlmngr_generateDefaultKey` and was found in `libwlmngr.so`.

### keygen.py
The C code re-written in Python.

### Firmware
Contains firmware files used for reverse engineering:
- [WIND Greece firmware](https://raw.githubusercontent.com/1nikolas/zyxel-wifi-keygen/refs/heads/main/Firmware/V100ABAP0b1_20151001.bin)

### Back_label_examples
Some photos found online to verify the keygen.


## How to use
Run the python version (`python keygen.py`).

Input the VDSL MAC Address (found using the Wi-Fi MAC as discussed previously, or directly by looking at the back label) and the following 2 values depending on the ISP:

| ISP | Mode | Key length | Back labels |
|---|---|---|---|
| WIND (Greece) | 2 | 8 | [1](https://raw.githubusercontent.com/1nikolas/zyxel-wifi-keygen/refs/heads/main/Back_label_examples/wind.jpg) |
| Generic | 2 | 20 | [1](https://raw.githubusercontent.com/1nikolas/zyxel-wifi-keygen/refs/heads/main/Back_label_examples/generic_1.jpg), [2](https://raw.githubusercontent.com/1nikolas/zyxel-wifi-keygen/refs/heads/main/Back_label_examples/generic_2.jpg), [3](https://raw.githubusercontent.com/1nikolas/zyxel-wifi-keygen/refs/heads/main/Back_label_examples/generic_3.jpg), [4](https://raw.githubusercontent.com/1nikolas/zyxel-wifi-keygen/refs/heads/main/Back_label_examples/generic_4.jpg) |
