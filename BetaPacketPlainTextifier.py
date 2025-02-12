# Packet Plaintext-ifier
import base64
import struct
from enum import Enum

class Origin(Enum):
    Server = 0
    Client = 1

class Packet(Enum):
    KeepAlive = 0x00
    LoginRequest = 0x01
    Handshake = 0x02
    ChatMessage = 0x03
    TimeUpdate = 0x04
    EntityEquipment = 0x05
    SpawnPosition = 0x06
    UseEntity = 0x07
    UpdateHealth = 0x08
    Respawn = 0x09
    Player = 0x0A
    PlayerPosition = 0x0B
    PlayerLook = 0x0C
    PlayerPositionLook = 0x0D
    PlayerDigging = 0x0E
    PlayerBlockPlacement = 0x0F
    HoldingChange = 0x10
    UseBed = 0x11
    Animation = 0x12
    EntityAction = 0x13
    NamedEntitySpawn = 0x14
    PickupSpawn = 0x15
    CollectItem = 0x16
    AddObjectVehicle = 0x17
    MobSpawn = 0x18
    EntityPainting = 0x19
    StanceUpdate = 0x1B
    EntityVelocity = 0x1C
    DestroyEntity = 0x1D
    Entity = 0x1E
    EntityRelativeMove = 0x1F
    EntityLook = 0x20
    EntityLookRelativeMove = 0x21
    EntityTeleport = 0x22
    EntityStatus = 0x26
    AttachEntity = 0x27
    EntityMetadata = 0x28
    PreChunk = 0x32
    Chunk = 0x33
    MultiBlockChange = 0x34
    BlockChange = 0x35
    BlockAction = 0x36
    Explosion = 0x3C
    Soundeffect = 0x3D
    NewInvalidState = 0x46
    Thunderbolt = 0x47
    OpenWindow = 0x64
    CloseWindow = 0x65
    WindowClick = 0x66
    SetSlot = 0x67
    WindowItems = 0x68
    UpdateProgressBar = 0x69
    Transaction = 0x6A
    UpdateSign = 0x82
    MapData = 0x83
    IncrementStatistic = 0xC8
    Disconnect = 0xFF

# i and packet needs to be global
# starting at 44 should skip the ethernet header
i = 0x42
packet = None

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

def PrintString16(name):
    stringLength = ReadShort()
    string = ""
    for c in range(stringLength):
        string += chr(ReadShort())
    PrintProperty(name,"String","\""+string+"\"")

def PrintProperty(name, t, content):
    print(f"\t({t}) {name}: {content}")

def PrintInventory():
    global i
    count = PrintShort("Count")
    for slot in range(count):
        itemId = PrintShort(f"[{slot}] Item")
        if (itemId != -1):
            PrintByte("Amount")
            PrintByte("Damage")


packet_b64 = "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"
origin = Origin.Server
packet = base64.b64decode(packet_b64)

while(i < len(packet)):
    # Store the PacketId
    packetId = packet[i]

    # Move to actual Data
    i += 1

    if packetId in Packet._value2member_map_:
        packetEnum = Packet._value2member_map_[packetId]
        print(f"--- {packetEnum.name} (0x{packetEnum.value:02X}) ---")
        match(packetEnum):
            case Packet.KeepAlive:
                pass
            case Packet.LoginRequest:
                if (origin == Origin.Client):
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
                if (origin == Origin.Client):
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
            case Packet.UseEntity:
                PrintInteger("EID (Sender)")
                PrintInteger("EID (Target)")
                PrintBoolean("Left-Click")
            case Packet.UpdateHealth:
                PrintShort("Health")
            case Packet.Respawn:
                PrintByte("Dimension")
            case Packet.Player:
                PrintBoolean("OnGround")
            case Packet.PlayerPosition:
                PrintDouble("x")
                PrintDouble("y")
                PrintDouble("stance")
                PrintDouble("z")
                PrintBoolean("OnGround")
            case Packet.PlayerLook:
                PrintFloat("Yawn")
                PrintFloat("Pitch")
                PrintBoolean("OnGround")
            case Packet.PlayerPositionLook:
                if (origin == Origin.Client):
                    PrintDouble("x")
                    PrintDouble("y")
                    PrintDouble("stance")
                    PrintDouble("z")
                    PrintFloat("Yawn")
                    PrintFloat("Pitch")
                    PrintBoolean("OnGround")
                else:
                    PrintDouble("x")
                    PrintDouble("stance")
                    PrintDouble("y")
                    PrintDouble("z")
                    PrintFloat("Yawn")
                    PrintFloat("Pitch")
                    PrintBoolean("OnGround")
            case Packet.PlayerDigging:
                PrintByte("Status")
                PrintInteger("x")
                PrintByte("y")
                PrintInteger("z")
                PrintByte("Face")
            case Packet.EntityRelativeMove:
                PrintInteger("EntityId")
                PrintByte("dX")
                PrintByte("dY")
                PrintByte("dZ")
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
            case Packet.WindowItems:
                PrintByte("Window")
                PrintInventory()
            case Packet.SetSlot:
                PrintByte("Window")
                slot = PrintShort("Slot")
                itemId = PrintShort(f"[{slot}] Item")
                if (itemId > -1):
                    PrintByte("Amount")
                    PrintShort("Damage")
            case Packet.Disconnect:
                PrintString16("Message")
            case _:
                pass
    else:
        print("UNHANDLED, FOLLOWING BYTES MAY BE DESYNCED")