# Packet Plaintext-ifier
import argparse
import struct
from enum import Enum
from pathlib import Path
import traceback

parser = argparse.ArgumentParser(
                    prog='BetaPacketPlainTextifier',
                    description='A simple python script to simplify the decoding and reading of TCP Data sent by a Minecraft Beta 1.7.3 Server.'
                    )
# Target Port
parser.add_argument('-sip', '--source', help='Source IP Address to extract data from')
# Target Port
parser.add_argument('-dip', '--destination', help='Destination IP Address to extract data from')
# Target Port
parser.add_argument('-p', '--port', help='Port to extract data from')
# Input Filename
parser.add_argument('-i', '--input', help='Input Capture File (.pcapng)')
# Output Filename
parser.add_argument('-o', '--output', help='Output Markdown File (.md)')
# Output to the CLI
parser.add_argument('-v', '--verbose',
                    action='store_true',
                    help="Print what the script is up to to the terminal")
# Output errors
parser.add_argument('-e', '--errors',
                    action='store_true',
                    help="Print Exceptions instead of ignoring them")

args = parser.parse_args()

packet = None
i = 0
faulty = False

capturePath = 'example/gameplay.pcapng'
source_ip_address = '127.0.0.1'
destination_ip_address = '127.0.0.1'
server_port = '25565'

if (args.source is not None):
    source_ip_address = args.source

if (args.destination is not None):
    destination_ip_address = args.destination

if (args.port is not None):
    server_port = args.port

if (args.input is not None):
    capturePath = args.input

outputPath = Path(capturePath).stem + ".md"
if (args.output is not None):
    outputPath = args.output

f = open(outputPath, "w")
f.write(f"| Sender | Packet | Data |\n")
f.write(f"| --- | --- | --- |\n")

server = "SERVER"

sender = server

class Packet(Enum):
    KeepAlive = 0x00
    LoginRequest = 0x01
    Handshake = 0x02
    ChatMessage = 0x03
    TimeUpdate = 0x04
    EntityEquipment = 0x05
    SpawnPosition = 0x06
    ClickEntity = 0x07
    SetHealth = 0x08
    Respawn = 0x09
    Player = 0x0A
    PlayerPosition = 0x0B
    PlayerLook = 0x0C
    PlayerPositionLook = 0x0D
    Mine = 0x0E
    Place = 0x0F
    ActiveSlot = 0x10
    UseBed = 0x11
    PlayerAction = 0x12
    EntityAction = 0x13
    SpawnPlayerEntity = 0x14
    SpawnItemEntity = 0x15
    CollectItem = 0x16
    SpawnObjectEntity = 0x17
    SpawnMobEntity = 0x18
    SpawnPaintingEntity = 0x19
    PlayerMovement = 0x1B
    EntityVelocity = 0x1C
    DestroyEntity = 0x1D
    Entity = 0x1E
    EntityRelativeMove = 0x1F
    EntityLook = 0x20
    EntityLookRelativeMove = 0x21
    EntityTeleport = 0x22
    EntityStatus = 0x26
    MountEntity = 0x27
    EntityMetadata = 0x28
    PreChunk = 0x32
    Chunk = 0x33
    MultiBlockUpdate = 0x34
    BlockUpdate = 0x35
    BlockAction = 0x36
    Explosion = 0x3C
    Effect = 0x3D
    GameState = 0x46
    LightningBolt = 0x47
    OpenInventory = 0x64
    CloseInventory = 0x65
    ClickInventorySlot = 0x66
    SetInventorySlot = 0x67
    InventoryContents = 0x68
    FurnaceProgress = 0x69
    InventoryTransaction = 0x6A
    UpdateSign = 0x82
    ItemData = 0x83
    Statistic = 0xC8
    Disconnect = 0xFF

def ReadByte():
    global i
    numByte = packet[i]
    i+=1
    return numByte

def ReadShort():
    global i
    numBytes = packet[i:i+2]
    i+=2
    return struct.unpack('>h', numBytes)[0]

def ReadInteger():
    global i
    numBytes = packet[i:i+4]
    i += 4
    return struct.unpack('>i', numBytes)[0]

def ReadLong():
    global i
    numBytes = packet[i:i+8]
    i += 8
    return struct.unpack('>q', numBytes)[0]

def ReadFloat():
    global i
    numBytes = packet[i:i+4]
    i += 4
    return struct.unpack('>f', numBytes)[0]

def ReadDouble():
    global i
    numBytes = packet[i:i+8]
    i += 8
    return struct.unpack('>d', numBytes)[0]
    
def PrintBoolean(name):
    result = ReadByte()
    PrintProperty(name,"Boolean",result)
    return result

def PrintByte(name):
    result = ReadByte()
    PrintProperty(name,"Byte",result)
    return result

def PrintShort(name):
    result = ReadShort()
    PrintProperty(name,"Short",result)
    return result

def PrintInteger(name):
    result = ReadInteger()
    PrintProperty(name,"Integer",result)
    return result

def PrintLong(name):
    result = ReadLong()
    PrintProperty(name,"Long",result)
    return result

def PrintFloat(name):
    result = ReadFloat()
    PrintProperty(name,"Float",result)
    return result

def PrintDouble(name):
    result = ReadDouble()
    PrintProperty(name,"Double",result)
    return result

def PrintString8(name):
    stringLength = ReadShort()
    string = ""
    for c in range(stringLength):
        string += chr(ReadByte())
    PrintProperty(name,"String","\""+string+"\"")

def PrintString16(name):
    stringLength = ReadShort()
    string = ""
    for c in range(stringLength):
        string += chr(ReadShort())
    PrintProperty(name,"String","\""+string+"\"")

def PrintInventory():
    global i
    count = PrintShort("Count")
    for slot in range(count):
        itemId = PrintShort(f"[{slot}] Item")
        if (itemId != -1):
            PrintByte("Amount")
            PrintByte("Damage")

def PrintProperty(name, t, content):
    if isinstance(content, float):
        content = f"{content:.2f}"
    if (args.verbose):
        print(f"\t`--({t}) {name}: {content}")
    f.write(f"{name}={content}; ")

def PrintBold(text, end='\n'):
    if (args.verbose):
        print(f"\033[1m{text}\033[0m",end=end)

def ReadPacket():
    global i
    global sender
    while(i < len(packet)):
        # Store the PacketId
        if (i > len(packet) or i < 0):
            break
        try:
            packetId = packet[i]
        except:
            # ignore
            print('',end="")

        # Move to actual Data
        i += 1

        if packetId in Packet._value2member_map_:
            packetEnum = Packet._value2member_map_[packetId]
            if (args.verbose):
                print(f"\t{packetEnum.name} (0x{packetEnum.value:02X})")
            f.write(f"| {sender} | {packetEnum.name} (0x{packetEnum.value:02X}) | ")
            match(packetEnum):
                case Packet.KeepAlive:
                    pass
                case Packet.LoginRequest:
                    if (sender != server):
                        PrintInteger("Protocol")
                        PrintString16("Username")
                        PrintLong("Seed")
                        PrintByte("Dimension")
                    else:
                        PrintInteger("EID")
                        PrintString16("Unknown")
                        PrintLong("Seed")
                        PrintByte("Dimension")
                case Packet.Handshake:
                    if (sender != server):
                        PrintString16("Username")
                    else:
                        PrintString16("Connection Hash")
                case Packet.ChatMessage:
                    PrintString16("Message")
                case Packet.TimeUpdate:
                    PrintLong("Time")
                case Packet.EntityEquipment:
                    PrintInteger("EID")
                    PrintShort("Slot")
                    PrintShort("Item")
                    PrintShort("Damage")
                case Packet.SpawnPosition:
                    PrintInteger("x")
                    PrintInteger("y")
                    PrintInteger("z")
                case Packet.ClickEntity:
                    PrintInteger("EID (Sender)")
                    PrintInteger("EID (Target)")
                    PrintBoolean("Left-Click")
                case Packet.SetHealth:
                    PrintShort("Health")
                case Packet.Respawn:
                    PrintByte("Dimension")
                case Packet.Player:
                    PrintBoolean("OnGround")
                case Packet.PlayerPosition:
                    PrintDouble("x")
                    PrintDouble("y")
                    PrintDouble("cameraY")
                    PrintDouble("z")
                    PrintBoolean("OnGround")
                case Packet.PlayerLook:
                    PrintFloat("Yaw")
                    PrintFloat("Pitch")
                    PrintBoolean("OnGround")
                case Packet.PlayerPositionLook:
                    if (sender != server):
                        PrintDouble("x")
                        PrintDouble("y")
                        PrintDouble("cameraY")
                        PrintDouble("z")
                        PrintFloat("Yaw")
                        PrintFloat("Pitch")
                        PrintBoolean("OnGround")
                    else:
                        PrintDouble("x")
                        PrintDouble("cameraY")
                        PrintDouble("y")
                        PrintDouble("z")
                        PrintFloat("Yaw")
                        PrintFloat("Pitch")
                        PrintBoolean("OnGround")
                case Packet.Mine:
                    PrintByte("Status")
                    PrintInteger("x")
                    PrintByte("y")
                    PrintInteger("z")
                    PrintByte("Face")
                case Packet.Place:
                    PrintInteger("x")
                    PrintByte("y")
                    PrintInteger("z")
                    PrintByte("Face")
                    item = PrintShort("Item")
                    if (item > -1):
                        PrintByte("Amount")
                        PrintShort("Damage")
                case Packet.ActiveSlot:
                    PrintShort("Slot")
                case Packet.UseBed:
                    PrintInteger("EID")
                    PrintByte("In Bed")
                    PrintInteger("x")
                    PrintByte("y")
                    PrintInteger("z")
                case Packet.PlayerAction:
                    PrintInteger("EID")
                    PrintByte("PlayerAction")
                case Packet.EntityAction:
                    PrintInteger("EID")
                    PrintByte("Action")
                case Packet.SpawnPlayerEntity:
                    PrintInteger("EID")
                    PrintString16("Username")
                    PrintInteger("x")
                    PrintInteger("y")
                    PrintInteger("z")
                    PrintByte("Yaw")
                    PrintByte("Pitch")
                    PrintShort("Held Item")
                case Packet.SpawnItemEntity:
                    PrintInteger("EID")
                    PrintShort("Item")
                    PrintByte("Amount")
                    PrintShort("Damage")
                    PrintInteger("x")
                    PrintInteger("y")
                    PrintInteger("z")
                    PrintByte("Yaw")
                    PrintByte("Pitch")
                    PrintByte("Roll")
                case Packet.CollectItem:
                    PrintInteger("EID (Collected)")
                    PrintInteger("EID (Collector)")
                case Packet.SpawnObjectEntity:
                    PrintInteger("EID")
                    PrintByte("Type")
                    PrintInteger("x")
                    PrintInteger("y")
                    PrintInteger("z")
                    PrintInteger("Flag?")
                    PrintShort("x?")
                    PrintShort("y?")
                    PrintShort("z?")
                case Packet.SpawnMobEntity:
                    PrintInteger("EID")
                    PrintByte("Type")
                    PrintInteger("x")
                    PrintInteger("y")
                    PrintInteger("z")
                    PrintByte("Yaw")
                    PrintByte("Pitch")
                    # TODO: implement mob metadata stream
                case Packet.SpawnPaintingEntity:
                    PrintInteger("EID")
                    PrintString16("Title")
                    PrintInteger("x")
                    PrintInteger("y")
                    PrintInteger("z")
                    PrintInteger("Face")
                case Packet.PlayerMovement:
                    PrintFloat("StrafeDir")
                    PrintFloat("ForwardDir")
                    PrintFloat("Pitch")
                    PrintFloat("Yaw")
                    PrintBoolean("Jumping")
                    PrintBoolean("Sneakin")
                case Packet.EntityVelocity:
                    PrintInteger("EID")
                    PrintShort("x Velocity")
                    PrintShort("y Velocity")
                    PrintShort("z Velocity")
                case Packet.DestroyEntity:
                    PrintInteger("EID")
                case Packet.Entity:
                    PrintInteger("EID")
                case Packet.EntityRelativeMove:
                    PrintInteger("EID")
                    PrintByte("dX")
                    PrintByte("dY")
                    PrintByte("dZ")
                case Packet.EntityLook:
                    PrintInteger("EID")
                    PrintByte("Yaw")
                    PrintByte("Pitch")
                case Packet.EntityLookRelativeMove:
                    PrintInteger("EID")
                    PrintByte("dX")
                    PrintByte("dY")
                    PrintByte("dZ")
                    PrintByte("Yaw")
                    PrintByte("Pitch")
                case Packet.EntityTeleport:
                    PrintInteger("EID")
                    PrintInteger("x")
                    PrintInteger("y")
                    PrintInteger("x")
                    PrintByte("Yaw")
                    PrintByte("Pitch")
                case Packet.EntityStatus:
                    PrintInteger("EID")
                    PrintByte("Status")
                case Packet.EntityMetadata:
                    PrintInteger("EID")
                    latestByte = ReadByte()
                    while(latestByte != 127):
                        selector = latestByte >> 5
                        match(selector):
                            case 0:
                                PrintByte("Byte")
                            case 1:
                                PrintShort("Shrt")
                            case 2:
                                PrintInteger("Int")
                            case 3:
                                PrintFloat("Flt")
                            case 4:
                                PrintString16("Str")
                            case 5:
                                PrintShort("Item")
                                PrintByte("Amount")
                                PrintShort("Damage")
                            case 6:
                                PrintInteger("Int1")
                                PrintInteger("Int2")
                                PrintInteger("Int3")
                        latestByte = ReadByte()
                    # TODO: implement mob metadata stream
                case Packet.PreChunk:
                    PrintInteger("x")
                    PrintInteger("z")
                    PrintBoolean("Mode")
                case Packet.Chunk:
                    PrintInteger("x")
                    PrintShort("y")
                    PrintInteger("x")
                    PrintByte("sizeX")
                    PrintByte("sizeY")
                    PrintByte("sizeZ")
                    size = PrintInteger("Compressed Size")
                    PrintProperty("Compressed Data","Byte[]","(Not included)")
                    i+=size
                case Packet.MultiBlockUpdate:
                    PrintInteger("x")
                    PrintInteger("z")
                    size = PrintShort("Array size")
                    PrintProperty("Coordinates","Byte[]","(Not included)")
                    i+=size*2
                    PrintProperty("Type","Byte[]","(Not included)")
                    i+=size
                    PrintProperty("Metadata","Byte[]","(Not included)")
                    i+=size
                case Packet.BlockUpdate:
                    PrintInteger("x")
                    PrintByte("y")
                    PrintInteger("z")
                    PrintByte("Type")
                    PrintByte("Meta")
                case Packet.BlockAction:
                    PrintInteger("x")
                    PrintByte("y")
                    PrintInteger("z")
                    PrintByte("Meta #1")
                    PrintByte("Meta #2")
                case Packet.Explosion:
                    PrintDouble("x")
                    PrintDouble("y")
                    PrintDouble("z")
                    PrintFloat("?")
                    # This one is documented poorly
                    count = PrintInteger("Count")
                    i+= count*3
                case Packet.Effect:
                    PrintInteger("Sound")
                    PrintInteger("x")
                    PrintByte("y")
                    PrintInteger("z")
                    PrintInteger("Data")
                case Packet.GameState:
                    # Apparently responsible for giving
                    # you the reason why you can't sleep.
                    PrintByte("Reason")
                case Packet.LightningBolt:
                    PrintInteger("EID")
                    PrintBoolean("?")
                    PrintInteger("x")
                    PrintInteger("y")
                    PrintInteger("z")
                case Packet.OpenInventory:
                    PrintByte("Window")
                    PrintByte("Inventory")
                    PrintString8("Title")
                    PrintByte("# of Slots")
                case Packet.CloseInventory:
                    PrintByte("Window")
                case Packet.ClickInventorySlot:
                    PrintByte("Window")
                    PrintShort("Slot")
                    PrintByte("Right-click")
                    PrintShort("Action number")
                    PrintBoolean("Shift")
                    item = PrintShort("Item")
                    if (item > -1):
                        PrintShort("Amount")
                        PrintShort("Damage")
                case Packet.SetInventorySlot:
                    PrintByte("Window")
                    slot = PrintShort("Slot")
                    itemId = PrintShort(f"[{slot}] Item")
                    if (itemId > -1):
                        PrintByte("Amount")
                        PrintShort("Damage")
                case Packet.InventoryContents:
                    PrintByte("Window")
                    PrintInventory()
                case Packet.FurnaceProgress:
                    PrintByte("Window")
                    PrintShort("Bar")
                    PrintShort("Progress")
                case Packet.InventoryTransaction:
                    PrintByte("Window")
                    PrintShort("Action number")
                    PrintBoolean("Accepted")
                case Packet.UpdateSign:
                    PrintInteger("x")
                    PrintShort("y")
                    PrintInteger("z")
                    PrintString16("Line 1")
                    PrintString16("Line 2")
                    PrintString16("Line 3")
                    PrintString16("Line 4")
                case Packet.ItemData:
                    PrintShort("?")
                    PrintShort("?")
                    length = PrintByte("Length")
                    # TODO: Handle this weird text?
                    i+=length
                case Packet.Statistic:
                    PrintInteger("Statistic")
                    PrintByte("Amount")
                case Packet.Disconnect:
                    PrintString16("Message")
                case _:
                    pass
            f.write(f"|\n")
        else:
            if (args.verbose):
                print(f"UNHANDLED (0x{packetId:02X}), FOLLOWING BYTES MAY BE DESYNCED")
            f.write(f"| {sender} | UNEXPECTED | 0x{packetId:02X} | \n")
    if (i > len(packet)):
        i = i%len(packet)
        if (args.verbose):
            print(f"--- Packet exceeds bounds, continuing in next packet at 0x{i:04X} ---")
    else:
        i = 0

import asyncio
import pyshark

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

cap = pyshark.FileCapture(capturePath, eventloop=loop)

# Iterate over the packets and filter for packets with source/destination IP 127.0.0.1
for packetIndex,dataPacket in enumerate(cap):
    if 'IP' in dataPacket and (dataPacket.ip.src == source_ip_address or dataPacket.ip.dst == destination_ip_address):
        # Print the data excluding the Ethernet header, which is part of layer 2
        # In PyShark, Ethernet headers are usually available as 'eth'
        #if hasattr(packet, 'ip'):
        #    print(packet.ip)  # Print IP-level information and data (excluding Ethernet header)
        # You can also print the TCP or UDP payload (this will exclude Ethernet header)
        if 'TCP' in dataPacket:
            try:
                if hasattr(dataPacket, "tcp") and hasattr(dataPacket.tcp, "payload") and dataPacket.tcp.payload:
                    if (len(dataPacket.tcp.payload) > 0): 
                        if (dataPacket.tcp.port == server_port):
                            if (args.verbose):
                                PrintBold(f"{server} ({server_port})")
                            sender = server
                        else:
                            if (args.verbose):
                                PrintBold(f"CLIENT ({dataPacket.tcp.port})")
                            sender = dataPacket.tcp.port
                        hex_payload = dataPacket.tcp.payload.replace(':', '')
                        # Convert hex string to byte array
                        packet = bytes.fromhex(hex_payload)
                        #packet = list(byte_packet)
                        #print(dataPacket.tcp.payload)
                        #print(packet)
                        if (args.verbose):
                            print(f"[{packetIndex+1}]", end='\t')
                        f.write(f"|-|-|**Start of Packet #{packetIndex+1}** [Size: {len(packet)}]|\n")
                        ReadPacket()
                        # Wait a bit
                        #input()
            except Exception as e:
                if (args.errors):
                    print(f"Exception occurred: {e}")
                    traceback.print_exc()
                pass
f.close()