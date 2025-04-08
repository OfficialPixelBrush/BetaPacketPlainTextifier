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
```bash
sudo wireshark
```
Reading via the Loopback Device, `Loopback:lo`, and using
```
ip.addr ==  127.0.0.1 && tcp.port eq 25565
```
as the filter seems to work quite well.

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
Running this script should be as easy as running the script.
```bash
python3 ./BetaPacketPlainTextifier.py
```

By default, this'll turn `example/gameplay.pcapng` into `gameplay.md`.

To change this, use `-i`/`--input` to pass in your own `.pcapng` file.

Additionally, if you'd like to place the output `.md` files elsewhere than the project directory, you can use `-o`/`--output`.

Use `-h`/`--help` to view any other parameters you can use.
