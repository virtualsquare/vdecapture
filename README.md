# vdecapture

`vdecapture` captures packet data from a live VDE network and saves it
to an output file in pcap format.

## Install

get the source code, from the root of the source tree run:
```
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
```

## Syntax

`vdecapture` [*options*] *VNL* *output file*


*VNL* is the Virtual Netowrk Locator as defined in vde_plug(1).
*output file* is the pathanme of the output file or "-" to write
data to the standard output.

## Options
  `-c` *npkts*, `--count` *npkts*
: Leave when *npkts* packets have been captured.

  `-s` *nbytes*, `--count` *nbytes*
: Set the maximum size of the output file to *nbytes* bytes.

  `-t` *secs*, `--time` *secs*
: Leave after *secs* seconds.

  `-a`, `--append`
: append data to the *output file* if that file already exists.

  `-q`, `--quiet`
: Do not print captured packeet counter on stderr.

  `-h`, `--help`
: Display a short help message and exit.

## Examples
```
vdecapture vde:///tmp/hub out.pcap
```
This command captures the packets received by the vde plug `hub:///tmp/hub` to the file `out.pcap`.
```
vdecapture vde:///tmp/hub - | wireshark -i - -k 
```
This command permits to trace live the packets on wireshark.

# Author
Renzo Davoli, VirtualSquare Team. 2023