# BetaPacketPlainTextifier
A simple python script to simplify the decoding and reading of TCP Data sent by a Minecraft Beta 1.7.3 Server.
This tool was mostly made to be used to help figure out how a Notchian Server works, to help develop [BetrockServer](https://github.com/OfficialPixelBrush/BetrockServer).

# Capturing
```bash
sudo wireshark
```
Reading via the Loopback Device, `Loopback:lo`, and using
```
ip.addr ==  127.0.0.1 && tcp.port eq 25565
```
as the filter seems to work quite well.

# Dependencies
```bash
sudo apt install tshark
```

# Running
```bash
source beta/bin/activate
```
