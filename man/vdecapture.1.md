<!--
.\" Copyright (C) 2023 VirtualSquare. Project Leader: Renzo Davoli
.\"
.\" This is free documentation; you can redistribute it and/or
.\" modify it under the terms of the GNU General Public License,
.\" as published by the Free Software Foundation, either version 2
.\" of the License, or (at your option) any later version.
.\"
.\" The GNU General Public License's references to "object code"
.\" and "executables" are to be interpreted as the output of any
.\" document formatting or typesetting system, including
.\" intermediate and printed output.
.\"
.\" This manual is distributed in the hope that it will be useful,
.\" but WITHOUT ANY WARRANTY; without even the implied warranty of
.\" MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
.\" GNU General Public License for more details.
.\"
.\" You should have received a copy of the GNU General Public
.\" License along with this manual; if not, write to the Free
.\" Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
.\" MA 02110-1301 USA.
.\"
-->
# NAME

vdecapture -- capture vde traffic in pcap format

# SYNOPSIS

`vdecapture` [*options*] *VNL* *output file*

# DESCRIPTION

`vdecapture` captures packet data from a live VDE network and saves it
to an output file in pcap format.

*VNL* is the Virtual Netowrk Locator as defined in vde_plug(1).
*output file* is the pathanme of the output file or "-" to write
data to the standard output.

# OPTIONS
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

# EXAMPLE

```
vdecapture vde:///tmp/hub out.pcap
```
This command captures the packets received by the vde plug `hub:///tmp/hub` to the file `out.pcap`.


```
vdecapture vde:///tmp/hub - | wireshark -i - -k 
```
This command permits to trace live the packets on wireshark.

# SEE ALSO
vde_plug(1)

# AUTHOR
VirtualSquare. Project leader: Renzo Davoli.

