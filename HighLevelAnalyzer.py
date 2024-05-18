# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

import time



# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    # my_number_setting = NumberSetting(min_value=0, max_value=1500000)

    command_names = {
        0x02: "FLASH_BEGIN",
        0x03: "FLASH_DATA",
        0x04: "FLASH_END",
        0x05: "MEM_BEGIN",
        0x06: "MEM_END",
        0x07: "MEM_DATA",
        0x08: "SYNC",
        0x09: "WRITE_REG",
        0x0a: "READ_REG",
        0x0b: "SPI_SET_PARAMS",
        0x0d: "SPI_ATTACH",
        0x0f: "CHANGE_BAUDRATE",
        0x10: "FLASH_DEFL_BEGIN",
        0x11: "FLASH_DEFL_DATA",
        0x12: "FLASH_DEFL_END",
        0x13: "SPI_FLASH_MD5",
        0x14: "GET_SECURITY_INFO",
        0xd0: "ERASE_FLASH",
        0xd1: "ERASE_REGION",
        0xd2: "READ_FLASH",
        0xd3: "RUN_USER_CODE"
    }

    checksum_commands = {0x07, 0x03, 0x11}  # MEM_DATA, FLASH_DATA, FLASH_DEFL_DATA
    inside_packet = False
    packet_start_time = None
    collected_data = []
    last_byte_time = None
    time_threshold = 0.01  # Time threshold in seconds
    pending_start = False  # Indicates a potential start of packet pending verification
    last_was_c0 = False
    previous_byte = 0x00

    def calculate_checksum(self, data):
        checksum = 0xEF
        for byte in data:
            checksum ^= byte
        return checksum


    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'ESP32 HLA': {
            'format': '{{data.input_type}}'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''

        # print("Settings:", self.my_number_setting)

    def unescape_slip(self, raw_data):
        escaped = False
        unescaped_data = []
        i = 0
        while i < len(raw_data):
            if escaped:
                if raw_data[i] == 0xDC:
                    unescaped_data.append(0xC0)
                elif raw_data[i] == 0xDD:
                    unescaped_data.append(0xDB)
                escaped = False
            elif raw_data[i] == 0xDB:
                escaped = True
            else:
                unescaped_data.append(raw_data[i])
            i += 1
        return unescaped_data
    
    def decode_packet(self, packet):

        try:
            if len(packet) < 8:
                return "Incomplete packet"

            direction = packet[0]
            command_identifier = packet[1]
            command_name = self.command_names.get(command_identifier, f"Unknown Command (0x{command_identifier:02X})")
            data_size = int.from_bytes(packet[2:4], 'little')

            if direction == 0x00:  # Request packets
                checksum = ' '.join(f'0x{b:02X}' for b in packet[4:8])
                field_description = f"checksum={checksum}"
                packet_type = "command"
            elif direction == 0x01:  # Response packets
                if command_identifier == 0x0a:  # READ_REG command
                    response_value = ' '.join(f'0x{b:02X}' for b in packet[4:8])
                    field_description = f"value={response_value}"
                else:
                    field_description = "value=0x00 0x00 0x00 0x00"
                packet_type = "response"
            else:
                packet_type = "Error"
                return f"Error Reading packet"

            actual_data = packet[8:]
            formatted_data = ' '.join(f'0x{b:02X}' for b in actual_data)
            data_mismatch = ""
            if len(actual_data) != data_size:
                data_mismatch = " (incorrect length of data payload)"

            # Checksum validation for specific commands
            if command_identifier in self.checksum_commands:
                if len(actual_data) >= 16:  # Ensure there is enough data for checksum calculation
                    data_to_write = actual_data[16:]
                    calculated_checksum = self.calculate_checksum(data_to_write)
                    if calculated_checksum != int.from_bytes(packet[4:8], 'little'):
                        checksum_message = f" (checksum of data (0x{calculated_checksum:02X}) does not match checksum field)"
                        field_description += checksum_message

            return f"{packet_type}: {command_name}, data_size={data_size}, {field_description}, data={formatted_data}{data_mismatch}"
        
        except Exception as e:
            return f"Error processing packet"

    def decode(self, frame: AnalyzerFrame):

        if frame.type != 'data':
            return None

        data = frame.data.get('data', None)
        if data is None:
            return None

        for byte in data:
            if byte == 0xC0:
                if self.inside_packet:
                    if len(self.collected_data) < 8:
                        #self.inside_packet = False
                        #self.collected_data = []
                        return None
                        # return  AnalyzerFrame('ESP32 HLA', self.packet_start_time, frame.end_time, {'input_type': "Incorrect Packet" })
                    # If already collecting a packet, this 0xC0 signifies the end.
                    unescaped_data = self.unescape_slip(self.collected_data)
                    message = self.decode_packet(unescaped_data)
                    result_frame = AnalyzerFrame('ESP32 HLA', self.packet_start_time, frame.end_time, {
                         'input_type': message
                    })
                    self.inside_packet = False
                    self.collected_data = []
                    return result_frame
                else:
                    # This 0xC0 signifies the start of a new packet.
                    self.inside_packet = True
                    self.packet_start_time = frame.start_time
                    self.collected_data = []
                    continue
            if self.inside_packet:
                self.collected_data.append(byte)
            self.previous_byte = byte

        return None
    
