# tunemu-linux
A port of tunemu for Linux, original website http://code.gerade.org/tunemu/

## FAQ

### 1. Why do we need to emulate tun/tap device under Linux?
We know Linux has builtin tun/tap modules however sometimes we can not get it on some embedded Linux devices. Device vendor may violate the GPL and refuse to supply the Linux kernel source code. Yes, you can charge them to open the source code but that will be a time/money consuming work.

### 2. How does tunemu work?
tunemu uses the kernel ppp driver to create a ppp device. It then reads packets from the ppp instance and writes packets to the loopback device using libpcap. 

### 3. What's the minimum requirement for tunemu?
You need kernel PPP driver, loopback interface 'lo' and libpcap to run tunemu.

### 4. Drawbacks of tunemu
The ppp interface RX statistics will be wrong.
