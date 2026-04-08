# goose-sniffer

Simple IEC 61850 GOOSE packet sniffer using `libpcap`.

## What it does

- Captures Ethernet frames from a network interface.
- Filters only GOOSE traffic (EtherType `0x88B8`), including VLAN-tagged frames (0x8100).
- Prints packet metadata and a hex/ASCII dump to stdout.

## Install libpcap

### On Debian/Ubuntu

```bash
sudo apt-get update
sudo apt-get install libpcap-dev
```

### On macOS

```bash
brew install libpcap
```

## Build

```bash
cmake -S . -B build
cmake --build build
```

or

```bash
mkdir build
cd build
cmake ..
make
```

## Run

Default interface (`en9`):

```bash
./build/goose-sniffer
```

Custom interface:

```bash
./build/goose-sniffer en0
```

```
Listening for IEC 61850 GOOSE packets on interface 'en9'.
Press Ctrl+C to stop.

=== GOOSE frame ===
Time: 2026-04-06 21:51:14.160107
Captured length: 256 bytes, original length: 256 bytes
Dst MAC: 01:0c:cd:01:00:01
Src MAC: 00:e0:5f:22:01:e1
EtherType: 0x88b8 (GOOSE)
Payload offset: 18 bytes
Hex dump:
  0000  01 0c cd 01 00 01 00 e0 5f 22 01 e1 81 00 80 01  |........_"......|
  0010  88 b8 10 00 00 ee 00 00 00 00 61 81 e3 80 29 73  |..........a...)s|
  0020  69 6d 70 6c 65 49 4f 47 65 6e 65 72 69 63 49 4f  |impleIOGenericIO|
  0030  2f 4c 4c 4e 30 24 47 4f 24 67 63 62 41 6e 61 6c  |/LLN0$GO$gcbAnal|
  0040  6f 67 56 61 6c 75 65 73 81 02 05 dc 82 23 73 69  |ogValues.....#si|
  0050  6d 70 6c 65 49 4f 47 65 6e 65 72 69 63 49 4f 2f  |mpleIOGenericIO/|
  0060  4c 4c 4e 30 24 41 6e 61 6c 6f 67 56 61 6c 75 65  |LLN0$AnalogValue|
  0070  73 83 06 61 6e 61 6c 6f 67 84 08 69 d4 00 a1 28  |s..analog..i...(|
  0080  b4 39 0a 85 02 01 ab 86 01 02 87 01 00 88 01 02  |.9..............|
  0090  89 01 00 8a 01 04 ab 68 a2 18 a2 07 87 05 08 42  |.......h.......B|
  00a0  2a 66 52 84 03 03 00 00 91 08 69 d4 00 a1 28 b4  |*fR.......i...(.|
  00b0  39 8a a2 18 a2 07 87 05 08 00 00 00 00 84 03 03  |9...............|
  00c0  00 00 91 08 00 00 00 00 00 00 00 00 a2 18 a2 07  |................|
  00d0  87 05 08 00 00 00 00 84 03 03 00 00 91 08 00 00  |................|
  00e0  00 00 00 00 00 00 a2 18 a2 07 87 05 08 00 00 00  |................|
  00f0  00 84 03 03 00 00 91 08 00 00 00 00 00 00 00 00  |................|
Decoded payload:
GOOSE decode:
  APPID: 0x1000
  Declared length: 238 bytes
  Reserved1: 0x0000, Reserved2: 0x0000
  gocbRef: simpleIOGenericIO/LLN0$GO$gcbAnalogValues
  timeAllowedToLive: 1500 ms
  datSet: simpleIOGenericIO/LLN0$AnalogValues
  goID: analog
  t: 2026-04-06 21:51:13.158999979 q=0x0a
  stNum: 427
  sqNum: 2
  test: false
  confRev: 2
  ndsCom: false
  numDatSetEntries: 4
  allData entries:
    [0] tag=0xa2, len=24, valueHex=a2 07 87 05 08 42 2a 66 52 84 03 03 00 00 91 08 69 d4 00 a1 28 b4 39 8a
    [1] tag=0xa2, len=24, valueHex=a2 07 87 05 08 00 00 00 00 84 03 03 00 00 91 08 00 00 00 00 00 00 00 00
    [2] tag=0xa2, len=24, valueHex=a2 07 87 05 08 00 00 00 00 84 03 03 00 00 91 08 00 00 00 00 00 00 00 00
    [3] tag=0xa2, len=24, valueHex=a2 07 87 05 08 00 00 00 00 84 03 03 00 00 91 08 00 00 00 00 00 00 00 00
```

## Notes

- On macOS, packet capture may require elevated privileges (`sudo`) depending on your environment.
- Stop capture with `Ctrl+C`.

