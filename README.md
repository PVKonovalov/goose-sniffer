# goose-sniffer

Simple IEC 61850 GOOSE packet sniffer using `libpcap`.

## What it does

- Captures Ethernet frames from a network interface.
- Filters only GOOSE traffic (EtherType `0x88B8`), including VLAN-tagged frames.
- Prints packet metadata and a hex/ASCII dump to stdout.


## Install libpcap
### On Debian/Ubuntu

```bash
sudo apt-get update
sudo apt-get install libpcap-dev
```

### On Macos

```bash
brew install libpcap
```

## Build

```bash
cmake -S . -B cmake-build-debug
cmake --build cmake-build-debug
```

## Run

Default interface (`en9`):

```bash
./cmake-build-debug/goose-sniffer
```

Custom interface:

```bash
./cmake-build-debug/goose-sniffer en0
```
```
Listening for IEC 61850 GOOSE packets on interface 'en9'.
Press Ctrl+C to stop.

=== GOOSE frame ===
Time: 2026-04-06 14:40:39.677141
Captured length: 255 bytes, original length: 255 bytes
Dst MAC: 01:0c:cd:01:00:01
Src MAC: 00:e0:5f:22:01:e1
EtherType: 0x88b8 (GOOSE)
Payload offset: 18 bytes
Hex dump:
  0000  01 0c cd 01 00 01 00 e0 5f 22 01 e1 81 00 80 01  |........_"......|
  0010  88 b8 10 00 00 ed 00 00 00 00 61 81 e2 80 29 73  |..........a...)s|
  0020  69 6d 70 6c 65 49 4f 47 65 6e 65 72 69 63 49 4f  |impleIOGenericIO|
  0030  2f 4c 4c 4e 30 24 47 4f 24 67 63 62 41 6e 61 6c  |/LLN0$GO$gcbAnal|
  0040  6f 67 56 61 6c 75 65 73 81 02 05 dc 82 23 73 69  |ogValues.....#si|
  0050  6d 70 6c 65 49 4f 47 65 6e 65 72 69 63 49 4f 2f  |mpleIOGenericIO/|
  0060  4c 4c 4e 30 24 41 6e 61 6c 6f 67 56 61 6c 75 65  |LLN0$AnalogValue|
  0070  73 83 06 61 6e 61 6c 6f 67 84 08 69 d3 9b b7 2d  |s..analog..i...-|
  0080  4f df 0a 85 01 10 86 01 01 87 01 00 88 01 02 89  |O...............|
  0090  01 00 8a 01 04 ab 68 a2 18 a2 07 87 05 08 3f c0  |......h.......?.|
  00a0  00 02 84 03 03 00 00 91 08 69 d3 9b b7 2d 4f df  |.........i...-O.|
  00b0  8a a2 18 a2 07 87 05 08 00 00 00 00 84 03 03 00  |................|
  00c0  00 91 08 00 00 00 00 00 00 00 00 a2 18 a2 07 87  |................|
  00d0  05 08 00 00 00 00 84 03 03 00 00 91 08 00 00 00  |................|
  00e0  00 00 00 00 00 a2 18 a2 07 87 05 08 00 00 00 00  |................|
  00f0  84 03 03 00 00 91 08 00 00 00 00 00 00 00 00     |...............|
```

## Notes

- On macOS, packet capture may require elevated privileges (`sudo`) depending on your environment.
- Stop capture with `Ctrl+C`.

