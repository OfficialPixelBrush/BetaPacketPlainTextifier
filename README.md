# BetaPacketPlainTextifier
A simple python script to simplify the decoding and reading of TCP Data sent by a Minecraft Beta 1.7.3 Server, by interpreting the Data inside of Wireshark captures.
This tool was mostly made to be used to help figure out how a Notchian Server works, to help develop [BetrockServer](https://github.com/OfficialPixelBrush/BetrockServer).

# Clone
First we clone the Repository.
```bash
git clone https://github.com/OfficialPixelBrush/BetaPacketPlainTextifier.git
cd BetaPacketPlainTextifier
```

# Capturing
If you're on Linux, you *may* need to run Wireshark with `sudo` to capture Localhost.
```bash
sudo wireshark
```

If your server is running locally, you need to read the data going through the Loopback Device, `Loopback:lo`. Use the following string to filter the packets.
```
ip.addr ==  127.0.0.1 && tcp.port eq 25565
```
This makes it so only packets going through the loopback device (`127.0.0.1`) are included, alongside any coming into or going out of port `25565`.

Change these if you're either running your server externally or if you're hosting it on a different port.

# Setup
Some Linux Distributions will prevent you from installing dependencies such as `pyshark` directly via `pip`.
As a result, you may need to create a `venv`.
```bash
python3 -m venv ./beta
```
Then enter that `venv` to make use of it.
```bash
source beta/bin/activate
```

# Dependencies
Install any required dependencies.
```bash
pip install -r requirements.txt
```

# Running
The script can be run as is.
```bash
python3 ./BetaPacketPlainTextifier.py
```

By default, this'll turn `example/gameplay.pcapng` into `gameplay.md`.

To change this, use `-i`/`--input` to pass in your own `.pcapng` file.

Additionally, if you'd like to place the output `.md` files elsewhere than the project directory, you can use `-o`/`--output`.

Use `-h`/`--help` to view any other parameters you can use.
