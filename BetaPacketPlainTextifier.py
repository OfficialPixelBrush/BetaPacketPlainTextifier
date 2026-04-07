# Packet Plaintext-ifier (fixed for multi-packet TCP reassembly)
import argparse
import struct
from enum import Enum
from pathlib import Path
import traceback
import markdown

parser = argparse.ArgumentParser(
                    prog='BetaPacketPlainTextifier',
                    description='A simple python script to simplify the decoding and reading of TCP Data sent by a Minecraft Beta 1.7.3 Server.'
                    )
parser.add_argument('-sip', '--source', help='Source IP Address to extract data from')
parser.add_argument('-dip', '--destination', help='Destination IP Address to extract data from')
parser.add_argument('-p', '--port', help='Port to extract data from')
parser.add_argument('-i', '--input', help='Input Capture File (.pcapng)')
parser.add_argument('-t', '--trigger', help='Packet ID to trigger on (e.g. "0x0A" or "PlayerPosition")')
parser.add_argument('-o', '--output', help='Output Markdown File (.md)')
parser.add_argument('-v', '--verbose', action='store_true', help='Print what the script is up to to the terminal')
parser.add_argument('-e', '--errors', action='store_true', help='Print Exceptions instead of ignoring them')
parser.add_argument('-th', '--tcp_header', help='Print TCP Header')
parser.add_argument('-html', '--html', action='store_true', help='Export as .html file')
args = parser.parse_args()

capturePath = 'example/gameplay.pcapng'
source_ip_address = '127.0.0.1'
destination_ip_address = '127.0.0.1'
server_port = '25565'

if args.source is not None:
    source_ip_address = args.source
if args.destination is not None:
    destination_ip_address = args.destination
if args.port is not None:
    server_port = args.port
if args.input is not None:
    capturePath = args.input

# TODO: Maybe have the default path fall back to where the .pcapng file is?
outputPath = Path(capturePath).stem + ".md"
if args.output is not None:
    outputPath = args.output

# Determines if data should be printed based on if the trigger packet has been seen yet.
# If no trigger is set, this will always be true.
trigger_packet_id = None
triggered = True
if args.trigger is not None:
    triggered = False
    trigger_packet_id = args.trigger
    if trigger_packet_id.lower().startswith('0x'):
        trigger_packet_id = int(trigger_packet_id, 16)

f = open(outputPath, 'w', encoding='utf-8')
f.write('| Sender | Packet | Data |\n')
f.write('| --- | --- | --- |\n')

server = 'SERVER'

class Packet(Enum):
    KeepAlive = 0x00
    Login = 0x01
    PreLogin = 0x02
    ChatMessage = 0x03
    SetTime = 0x04
    SetEquipment = 0x05
    SetSpawnPosition = 0x06
    InteractWithEntity = 0x07
    SetHealth = 0x08
    Respawn = 0x09
    PlayerMovement = 0x0A
    PlayerPosition = 0x0B
    PlayerRotation = 0x0C
    PlayerPositionAndRotation = 0x0D
    MineBlock = 0x0E
    PlaceBlock = 0x0F
    SetHotbarSlot = 0x10
    InteractWithBlock = 0x11
    Animation = 0x12
    PlayerAction = 0x13
    SpawnPlayer = 0x14
    SpawnItem = 0x15
    CollectItem = 0x16
    SpawnObject = 0x17
    SpawnMob = 0x18
    SpawnPainting = 0x19
    PlayerInput = 0x1B
    EntityVelocity = 0x1C
    DespawnEntity = 0x1D
    EntityMovement = 0x1E
    EntityPosition = 0x1F
    EntityRotation = 0x20
    EntityPositionAndRotation = 0x21
    TeleportEntity = 0x22
    EntityEvent = 0x26
    AddPassenger = 0x27
    EntityMetadata = 0x28
    SetChunkVisibility = 0x32
    Chunk = 0x33
    SetMutlipleBlocks = 0x34
    SetBlock = 0x35
    BlockEvent = 0x36
    Explosion = 0x3C
    WorldEvent = 0x3D
    GameEvent = 0x46
    LightningBolt = 0x47
    OpenContainer = 0x64
    CloseContainer = 0x65
    ClickSlot = 0x66
    SetSlot = 0x67
    FillContainer = 0x68
    ContainerData = 0x69
    ContainerTransaction = 0x6A
    UpdateSign = 0x82
    ItemData = 0x83
    IncrementStatistic = 0xC8
    Disconnect = 0xFF


class ParseError(Exception):
    pass

if args.trigger is not None and not isinstance(trigger_packet_id, int):
    trigger_lower_map = {name.lower(): member.value for name, member in Packet.__members__.items()}
    trigger_lookup = trigger_packet_id.lower()
    if trigger_lookup in trigger_lower_map:
        trigger_packet_id = trigger_lower_map[trigger_lookup]
    else:
        raise ValueError(f'Unknown trigger packet id: {args.trigger}')


class PacketParser:
    def __init__(self, packet_bytes, sender):
        self.packet = packet_bytes
        self.sender = sender
        self.i = 0
        self.out = []

    def _read(self, n):
        if self.i + n > len(self.packet):
            raise ParseError('incomplete packet')
        v = self.packet[self.i:self.i + n]
        self.i += n
        return v

    def read_byte(self):
        return self._read(1)[0]

    def read_short(self):
        return struct.unpack('>h', self._read(2))[0]

    def read_integer(self):
        return struct.unpack('>i', self._read(4))[0]

    def read_long(self):
        return struct.unpack('>q', self._read(8))[0]

    def read_float(self):
        return struct.unpack('>f', self._read(4))[0]

    def read_double(self):
        return struct.unpack('>d', self._read(8))[0]

    def read_mob_metadata(self):
        while(True):
            latest_byte = self.read_byte()
            if latest_byte == 127:
                break
            selector = latest_byte >> 5
            match selector:
                case 0:
                    self.read_byte()
                case 1:
                    self.read_short()
                case 2:
                    self.read_integer()
                case 3:
                    self.read_float()
                case 4:
                    self.print_string16('Str')
                case 5:
                    self.read_short() # Item
                    self.read_byte() # Amount
                    self.read_short() # Damage
                case 6:
                    self.read_integer() # Int1
                    self.read_integer() # Int2
                    self.read_integer() # Int3
        return 'Metadata'

    def read_multi_block_update(self, size):
        for _ in range(size):
            self.read_short() # block position
        for _ in range(size):
         self.read_byte() # block type
        for _ in range(size):
            self.read_byte() # block meta
        return 'MB Info'

    def print_property(self, name, t, content):
        if isinstance(content, float):
            content = f'{content:.2f}'
        self.out.append(f'{name}={content}; ')

    def print_string16(self, name):
        string_length = self.read_short()
        if string_length < 0:
            raise ParseError('negative string length')
        chars = []
        for _ in range(string_length):
            chars.append(chr(self.read_short()))
        value = '"' + ''.join(chars) + '"'
        self.print_property(name, 'String', value)

    def print_string8(self, name):
        string_length = self.read_short()
        if string_length < 0:
            raise ParseError('negative string length')
        chars = []
        for _ in range(string_length):
            chars.append(chr(self.read_byte()))
        value = '"' + ''.join(chars) + '"'
        self.print_property(name, 'String', value)

    def print_inventory(self):
        count = self.read_short()
        self.print_property('Count', 'Short', count)
        for slot in range(count):
            item_id = self.read_short()
            #self.print_property(f'[{slot}] Item', 'Short', item_id)
            if item_id != -1:
                amount = self.read_byte(); #self.print_property('Amount', 'Byte', amount)
                damage = self.read_byte(); #self.print_property('Damage', 'Byte', damage)

    def parse_one_packet(self):
        packet_id = self.read_byte()
        
        if packet_id not in Packet._value2member_map_:
            self.out = [f'0x{packet_id:02X}']
            return packet_id

        packet_enum = Packet._value2member_map_[packet_id]
        self.packet_id = packet_id

        match packet_enum:
            case Packet.KeepAlive:
                pass
            case Packet.Login:
                if self.sender != server:
                    self.print_property('Protocol', 'Integer', self.read_integer())
                    self.print_string16('Username')
                    self.print_property('Seed', 'Long', self.read_long())
                    self.print_property('Dimension', 'Byte', self.read_byte())
                else:
                    self.print_property('EID', 'Integer', self.read_integer())
                    self.print_string16('Unknown')
                    self.print_property('Seed', 'Long', self.read_long())
                    self.print_property('Dimension', 'Byte', self.read_byte())
            case Packet.PreLogin:
                if self.sender != server:
                    self.print_string16('Username')
                else:
                    self.print_string16('Connection Hash')
            case Packet.ChatMessage:
                self.print_string16('Message')
            case Packet.SetTime:
                self.print_property('Time', 'Long', self.read_long())
            case Packet.SetEquipment:
                self.print_property('EID', 'Integer', self.read_integer())
                self.print_property('Slot', 'Short', self.read_short())
                self.print_property('Item', 'Short', self.read_short())
                self.print_property('Damage', 'Short', self.read_short())
            case Packet.SetSpawnPosition:
                self.print_property('x', 'Integer', self.read_integer())
                self.print_property('y', 'Integer', self.read_integer())
                self.print_property('z', 'Integer', self.read_integer())
            case Packet.InteractWithEntity:
                self.print_property('EID (Sender)', 'Integer', self.read_integer())
                self.print_property('EID (Target)', 'Integer', self.read_integer())
                self.print_property('Left-Click', 'Boolean', self.read_byte())
            case Packet.SetHealth:
                self.print_property('Health', 'Short', self.read_short())
            case Packet.Respawn:
                self.print_property('Dimension', 'Byte', self.read_byte())
            case Packet.PlayerMovement:
                self.print_property('OnGround', 'Boolean', self.read_byte())
            case Packet.PlayerPosition:
                self.print_property('x', 'Double', self.read_double())
                self.print_property('y', 'Double', self.read_double())
                self.print_property('cameraY', 'Double', self.read_double())
                self.print_property('z', 'Double', self.read_double())
                self.print_property('OnGround', 'Boolean', self.read_byte())
            case Packet.PlayerRotation:
                self.print_property('Yaw', 'Float', self.read_float())
                self.print_property('Pitch', 'Float', self.read_float())
                self.print_property('OnGround', 'Boolean', self.read_byte())
            case Packet.PlayerPositionAndRotation:
                self.print_property('x', 'Double', self.read_double())
                self.print_property('y', 'Double', self.read_double())
                self.print_property('cameraY', 'Double', self.read_double())
                self.print_property('z', 'Double', self.read_double())
                self.print_property('Yaw', 'Float', self.read_float())
                self.print_property('Pitch', 'Float', self.read_float())
                self.print_property('OnGround', 'Boolean', self.read_byte())
            case Packet.MineBlock:
                self.print_property('Status', 'Byte', self.read_byte())
                self.print_property('x', 'Integer', self.read_integer())
                self.print_property('y', 'Byte', self.read_byte())
                self.print_property('z', 'Integer', self.read_integer())
                self.print_property('Face', 'Byte', self.read_byte())
            case Packet.PlaceBlock:
                self.print_property('x', 'Integer', self.read_integer())
                self.print_property('y', 'Byte', self.read_byte())
                self.print_property('z', 'Integer', self.read_integer())
                self.print_property('Face', 'Byte', self.read_byte())
                item_id = self.read_short(); self.print_property('Item', 'Short', item_id)
                if item_id > -1:
                    self.print_property('Amount', 'Byte', self.read_byte())
                    self.print_property('Damage', 'Short', self.read_short())
            case Packet.SetHotbarSlot:
                self.print_property('Slot', 'Short', self.read_short())
            case Packet.InteractWithBlock:
                self.print_property('EID', 'Integer', self.read_integer())
                self.print_property('In Bed', 'Byte', self.read_byte())
                self.print_property('x', 'Integer', self.read_integer())
                self.print_property('y', 'Byte', self.read_byte())
                self.print_property('z', 'Integer', self.read_integer())
            case Packet.Animation:
                self.print_property('EID', 'Integer', self.read_integer())
                self.print_property('Animation', 'Byte', self.read_byte())
            case Packet.PlayerAction:
                self.print_property('EID', 'Integer', self.read_integer())
                self.print_property('Action', 'Byte', self.read_byte())
            case Packet.SpawnPlayer:
                self.print_property('EID', 'Integer', self.read_integer())
                self.print_string16('Username')
                self.print_property('x', 'Integer', self.read_integer())
                self.print_property('y', 'Integer', self.read_integer())
                self.print_property('z', 'Integer', self.read_integer())
                self.print_property('Yaw', 'Byte', self.read_byte())
                self.print_property('Pitch', 'Byte', self.read_byte())
                self.print_property('Held Item', 'Short', self.read_short())
            case Packet.SpawnItem:
                self.print_property('EID', 'Integer', self.read_integer())
                self.print_property('Item', 'Short', self.read_short())
                self.print_property('Amount', 'Byte', self.read_byte())
                self.print_property('Damage', 'Short', self.read_short())
                self.print_property('x', 'Integer', self.read_integer())
                self.print_property('y', 'Integer', self.read_integer())
                self.print_property('z', 'Integer', self.read_integer())
                self.print_property('Yaw', 'Byte', self.read_byte())
                self.print_property('Pitch', 'Byte', self.read_byte())
                self.print_property('Roll', 'Byte', self.read_byte())
            case Packet.CollectItem:
                self.print_property('EID (Collected)', 'Integer', self.read_integer())
                self.print_property('EID (Collector)', 'Integer', self.read_integer())
            case Packet.SpawnObject:
                self.print_property('EID', 'Integer', self.read_integer())
                self.print_property('Type', 'Byte', self.read_byte())
                self.print_property('x', 'Integer', self.read_integer())
                self.print_property('y', 'Integer', self.read_integer())
                self.print_property('z', 'Integer', self.read_integer())
                owner_eid = self.read_integer()
                self.print_property('Owner EID', 'Integer', owner_eid)
                if (owner_eid > 0):
                    self.print_property('x velocity', 'Short', self.read_short())
                    self.print_property('y velocity', 'Short', self.read_short())
                    self.print_property('z velocity', 'Short', self.read_short())
            case Packet.SpawnMob:
                self.print_property('EID', 'Integer', self.read_integer())
                self.print_property('Type', 'Byte', self.read_byte())
                self.print_property('x', 'Integer', self.read_integer())
                self.print_property('y', 'Integer', self.read_integer())
                self.print_property('z', 'Integer', self.read_integer())
                self.print_property('Yaw', 'Byte', self.read_byte())
                self.print_property('Pitch', 'Byte', self.read_byte())
                self.read_mob_metadata()
                #self.print_property('Metadata', 'Multi', self.read_mob_metadata())
            case Packet.SpawnPainting:
                self.print_property('EID', 'Integer', self.read_integer())
                self.print_string16('Title')
                self.print_property('x', 'Integer', self.read_integer())
                self.print_property('y', 'Integer', self.read_integer())
                self.print_property('z', 'Integer', self.read_integer())
                self.print_property('Face', 'Integer', self.read_integer())
            case Packet.PlayerInput:
                self.print_property('StrafeDir', 'Float', self.read_float())
                self.print_property('ForwardDir', 'Float', self.read_float())
                self.print_property('Pitch', 'Float', self.read_float())
                self.print_property('Yaw', 'Float', self.read_float())
                self.print_property('Jumping', 'Boolean', self.read_byte())
                self.print_property('Sneakin', 'Boolean', self.read_byte())
            case Packet.EntityVelocity:
                self.print_property('EID', 'Integer', self.read_integer())
                self.print_property('x Velocity', 'Short', self.read_short())
                self.print_property('y Velocity', 'Short', self.read_short())
                self.print_property('z Velocity', 'Short', self.read_short())
            case Packet.DespawnEntity:
                self.print_property('EID', 'Integer', self.read_integer())
            case Packet.EntityMovement:
                self.print_property('EID', 'Integer', self.read_integer())
            case Packet.EntityPosition:
                self.print_property('EID', 'Integer', self.read_integer())
                self.print_property('dX', 'Byte', self.read_byte())
                self.print_property('dY', 'Byte', self.read_byte())
                self.print_property('dZ', 'Byte', self.read_byte())
            case Packet.EntityRotation:
                self.print_property('EID', 'Integer', self.read_integer())
                self.print_property('Yaw', 'Byte', self.read_byte())
                self.print_property('Pitch', 'Byte', self.read_byte())
            case Packet.EntityPositionAndRotation:
                self.print_property('EID', 'Integer', self.read_integer())
                self.print_property('dX', 'Byte', self.read_byte())
                self.print_property('dY', 'Byte', self.read_byte())
                self.print_property('dZ', 'Byte', self.read_byte())
                self.print_property('Yaw', 'Byte', self.read_byte())
                self.print_property('Pitch', 'Byte', self.read_byte())
            case Packet.TeleportEntity:
                self.print_property('EID', 'Integer', self.read_integer())
                self.print_property('x', 'Integer', self.read_integer())
                self.print_property('y', 'Integer', self.read_integer())
                self.print_property('z', 'Integer', self.read_integer())
                self.print_property('Yaw', 'Byte', self.read_byte())
                self.print_property('Pitch', 'Byte', self.read_byte())
            case Packet.EntityEvent:
                self.print_property('EID', 'Integer', self.read_integer())
                self.print_property('Status', 'Byte', self.read_byte())
            case Packet.AddPassenger:
                self.print_property('EID (passenger)', 'Integer', self.read_integer())
                self.print_property('EID (vehicle)', 'Integer', self.read_integer())
            case Packet.EntityMetadata:
                self.print_property('EID', 'Integer', self.read_integer())
                self.read_mob_metadata()
            case Packet.SetChunkVisibility:
                self.print_property('x', 'Integer', self.read_integer())
                self.print_property('z', 'Integer', self.read_integer())
                self.print_property('Mode', 'Boolean', self.read_byte())
            case Packet.Chunk:
                self.print_property('x', 'Integer', self.read_integer())
                self.print_property('y', 'Short', self.read_short())
                self.print_property('z', 'Integer', self.read_integer())
                self.print_property('sizeX', 'Byte', self.read_byte())
                self.print_property('sizeY', 'Byte', self.read_byte())
                self.print_property('sizeZ', 'Byte', self.read_byte())
                size = self.read_integer()
                self.print_property('Compressed Size', 'Integer', size)
                #self.print_property('Compressed Data', 'Byte[]', '(Not included)')
                for _ in range(size):
                    self.read_byte()
            case Packet.SetMutlipleBlocks:
                self.print_property('x', 'Integer', self.read_integer())
                self.print_property('z', 'Integer', self.read_integer())
                size = self.read_short()
                self.print_property('Array size', 'Short', size)
                self.read_multi_block_update(size)
                #self.print_property('MB Info', 'Short[], Byte[], Byte[]', self.read_multi_block_update(size))
            case Packet.SetBlock:
                self.print_property('x', 'Integer', self.read_integer())
                self.print_property('y', 'Byte', self.read_byte())
                self.print_property('z', 'Integer', self.read_integer())
                self.print_property('Type', 'Byte', self.read_byte())
                self.print_property('Meta', 'Byte', self.read_byte())
            case Packet.BlockEvent:
                self.print_property('x', 'Integer', self.read_integer())
                self.print_property('y', 'Byte', self.read_byte())
                self.print_property('z', 'Integer', self.read_integer())
                self.print_property('Meta #1', 'Byte', self.read_byte())
                self.print_property('Meta #2', 'Byte', self.read_byte())
            case Packet.Explosion:
                self.print_property('x', 'Double', self.read_double())
                self.print_property('y', 'Double', self.read_double())
                self.print_property('z', 'Double', self.read_double())
                self.print_property('?', 'Float', self.read_float())
                count = self.read_integer()
                self.print_property('Count', 'Integer', count)
                self.i += count * 3
            case Packet.WorldEvent:
                self.print_property('Sound', 'Integer', self.read_integer())
                self.print_property('x', 'Integer', self.read_integer())
                self.print_property('y', 'Byte', self.read_byte())
                self.print_property('z', 'Integer', self.read_integer())
                self.print_property('Data', 'Integer', self.read_integer())
            case Packet.GameEvent:
                self.print_property('Reason', 'Byte', self.read_byte())
            case Packet.LightningBolt:
                self.print_property('EID', 'Integer', self.read_integer())
                self.print_property('?', 'Boolean', self.read_byte())
                self.print_property('x', 'Integer', self.read_integer())
                self.print_property('y', 'Integer', self.read_integer())
                self.print_property('z', 'Integer', self.read_integer())
            case Packet.OpenContainer:
                self.print_property('Window', 'Byte', self.read_byte())
                self.print_property('Inventory', 'Byte', self.read_byte())
                self.print_string8('Title')
                self.print_property('# of Slots', 'Byte', self.read_byte())
            case Packet.CloseContainer:
                self.print_property('Window', 'Byte', self.read_byte())
            case Packet.ClickSlot:
                self.print_property('Window', 'Byte', self.read_byte())
                self.print_property('Slot', 'Short', self.read_short())
                self.print_property('Right-click', 'Byte', self.read_byte())
                self.print_property('Action number', 'Short', self.read_short())
                self.print_property('Shift', 'Boolean', self.read_byte())
                item_id = self.read_short(); self.print_property('Item', 'Short', item_id)
                if item_id > -1:
                    self.print_property('Amount', 'Short', self.read_short())
                    self.print_property('Damage', 'Short', self.read_short())
            case Packet.SetSlot:
                self.print_property('Window', 'Byte', self.read_byte())
                slot = self.read_short(); self.print_property('Slot', 'Short', slot)
                item_id = self.read_short(); self.print_property(f'[{slot}] Item', 'Short', item_id)
                if item_id > -1:
                    self.print_property('Amount', 'Byte', self.read_byte())
                    self.print_property('Damage', 'Short', self.read_short())
            case Packet.FillContainer:
                self.print_property('Window', 'Byte', self.read_byte())
                self.print_inventory()
            case Packet.ContainerData:
                self.print_property('Window', 'Byte', self.read_byte())
                self.print_property('Bar', 'Short', self.read_short())
                self.print_property('Progress', 'Short', self.read_short())
            case Packet.ContainerTransaction:
                self.print_property('Window', 'Byte', self.read_byte())
                self.print_property('Action number', 'Short', self.read_short())
                self.print_property('Accepted', 'Boolean', self.read_byte())
            case Packet.UpdateSign:
                self.print_property('x', 'Integer', self.read_integer())
                self.print_property('y', 'Short', self.read_short())
                self.print_property('z', 'Integer', self.read_integer())
                self.print_string16('Line 1')
                self.print_string16('Line 2')
                self.print_string16('Line 3')
                self.print_string16('Line 4')
            case Packet.ItemData:
                self.print_property('?', 'Short', self.read_short())
                self.print_property('?', 'Short', self.read_short())
                length = self.read_byte(); self.print_property('Length', 'Byte', length)
                self.i += length
            case Packet.IncrementStatistic:
                self.print_property('IncrementStatistic', 'Integer', self.read_integer())
                self.print_property('Amount', 'Byte', self.read_byte())
            case Packet.Disconnect:
                self.print_string16('Message')
            case _:
                pass

        return packet_enum


def process_buffer(buffer, sender, tcp_header_line=None):
    global triggered
    off = 0
    header_written = False
    while off < len(buffer):
        parser = PacketParser(buffer[off:], sender)
        try:
            packet_enum = parser.parse_one_packet()
            payload_string = ''.join(parser.out)
            packet_id = parser.packet_id
            is_trigger_packet = trigger_packet_id is not None and packet_id == trigger_packet_id
            if not triggered and is_trigger_packet:
                triggered = True

            if triggered:
                if tcp_header_line and not header_written:
                    f.write(tcp_header_line)
                    header_written = True
                if isinstance(packet_enum, Packet):
                    f.write(f'| {sender} | {packet_enum.name} (0x{packet_enum.value:02X}) | {payload_string} |\n')
                    if args.verbose:
                        print(f'\tParsed {packet_enum.name}')
                else:
                    f.write(f'| {sender} | UNEXPECTED | 0x{packet_id:02X} |\n')
                    if args.verbose:
                        print(f'\tParsed UNEXPECTED 0x{packet_id:02X}')
            off += parser.i
        except ParseError:
            break
        except Exception as e:
            if args.errors:
                print(f'Exception occurred: {e}')
                traceback.print_exc()
            break

    return buffer[off:]


import asyncio
import pyshark

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

cap = pyshark.FileCapture(capturePath, eventloop=loop)

stream_buffers = {}

for packetIndex, dataPacket in enumerate(cap):
    if 'IP' not in dataPacket:
        continue
    if dataPacket.ip.src != source_ip_address and dataPacket.ip.dst != destination_ip_address:
        continue

    if 'TCP' not in dataPacket:
        continue

    try:
        if not hasattr(dataPacket.tcp, 'payload') or not dataPacket.tcp.payload:
            continue

        hex_payload = dataPacket.tcp.payload.replace(':', '')
        if not hex_payload:
            continue

        payload = bytes.fromhex(hex_payload)
        if not payload:
            continue

        src = dataPacket.ip.src
        dst = dataPacket.ip.dst
        src_port = dataPacket.tcp.srcport
        dst_port = dataPacket.tcp.dstport

        stream_key = (src, dst, src_port, dst_port)
        stream_buffer = stream_buffers.setdefault(stream_key, bytearray())
        stream_buffer.extend(payload)

        if dataPacket.tcp.port == server_port:
            if args.verbose:
                print(f'{server} ({server_port})')
            sender_label = server
        else:
            if args.verbose:
                print(f'CLIENT ({dataPacket.tcp.port})')
            sender_label = f'CLIENT:{dataPacket.tcp.port}'

        if args.tcp_header:
            tcp_header_line = f'|-|-|**Start of TCP segment #{packetIndex + 1}** [Size: {len(payload)}]|\n'
        else:
            tcp_header_line = None

        remainder = process_buffer(stream_buffer, sender_label, tcp_header_line)
        stream_buffers[stream_key] = bytearray(remainder)

    except Exception as e:
        if args.errors:
            print(f'Exception occurred while processing packet {packetIndex + 1}: {e}')
            traceback.print_exc()
        continue

f.close()

if args.html:
    with open(outputPath, 'r', encoding='utf-8') as md_file:
        md_content = md_file.read()
    html_content = markdown.markdown(md_content, extensions=['tables'])
    html_output_path = Path(outputPath).with_suffix('.html')
    with open(html_output_path, 'w', encoding='utf-8') as html_file:
        html_file.write(html_content)
