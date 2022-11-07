# ISA  Project -netflow exporter
Netflow exporter _flow_ is a C++ application, serving for network analysis. The application creates NetFlow records from the captured network data in pcap format, which it sends to the netflow collector through an udp client. 
Created 22.10.2022
## Contributors

*Lucia Makaiová*  [xmakai00]

### Running the program

$ Use make to build the program. 
$ Run the program 
  ```
  ./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]
  ```

  For example.

  ```
  ./flow -c 127.0.0.1 -f test.pcap -i 13

  ```

$ Possible arguments to specify program behaviour:
+ -h -prints help 
+ -f <file> -name of the analysed file (default = STDIN)
+ -c <neflow_collector:port> -IP address, or hostname of the NetFlow collector (default = 127.0.0.1:2055)
+ -a <active_timer>  - interval in seconds, after which the active flows are exported (default = 60)
+ -i <seconds>       - interval in seconds, after which the inactive flows are exported (default = 10)
+ -m <count>         - flow-cache size (default = 1024)
Note: Arguments can be written in any order. 

## Usage

Usage examples:

  ```
Target:	Export netflow from test.pcap to host 127.0.0.1:2005(set maximum duration of 1 flow to 13s):
Call:	./flow -c 127.0.0.1:2005 -f test.pcap -i 13

Output:	Use tools such as nfcapf and nfdump to collect _flow_ output and display it.

  ```
  ```


## List of files
Source files:
+ flow.h
+ flow.cpp
+ netflow_generator.h
+ netflow_generator.cpp
+ arguments.h
+ arguments.cpp
Additional files:
+ manual.pdf (documentation)
+ makefile

