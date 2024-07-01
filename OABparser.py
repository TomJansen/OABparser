#!/usr/bin/env python3

import struct
from io import BytesIO
import math
import binascii
import json

from schema import PidTagSchema

#Details: https://msopenspecs.azureedge.net/files/MS-OXOAB/%5bMS-OXOAB%5d.pdf

def hex(value):
    # standard hex formatting, paddings with a length of 8 (32-bit integer)
    width = 8
    return f'0x{value:0{width}X}'
    
def get_prop_type(PropID):
    # The property type is infered from the last 2 bytes of PropID
    typebytes = PropID[-4:]
    if typebytes == "0003":
        return "PtypInteger32"
    elif typebytes == "000B":
        return "PtypBoolean"
    elif typebytes == "000D":
        return "PtypObject"
    elif typebytes == "001E":
        return "PtypString8"
    elif typebytes == "001F":
        return "PtypString"
    elif typebytes == "0102":
        return "PtypBinary"
    elif typebytes == "1003":
        return "PtypMultipleInteger32"
    elif typebytes == "101E":
        return "PtypMultipleString8"
    elif typebytes == "101F":
        return "PtypMultipleString"
    elif typebytes == "1102":
        return "PtypMultipleBinary"
    else:
        return "Unknown(ProdID=%s)" % PropID

def handle_property(Type):      
    if Type in ["PtypString8", "PtypString"]:
        val = PtypString_to_str()
        return val
    elif Type == "PtypBoolean":
        val = struct.unpack('<?', chunk.read(1))[0]
        return val
    elif Type == "PtypInteger32":
        val = PtypInteger32_to_int()
        return val
    elif Type == "PtypBinary":
        bin_data = chunk.read(PtypInteger32_to_int())
        val = binascii.b2a_hex(bin_data).decode()
        return val
    elif Type in ["PtypMultipleString", "PtypMultipleString8"]:
        byte_count = PtypInteger32_to_int()
        arr = []
        for j in range(byte_count):
            val = PtypString_to_str()
            arr.append(val)
        return arr
    elif Type == "PtypMultipleInteger32":
        byte_count = PtypInteger32_to_int()
        arr = []
        for j in range(byte_count):
            val = PtypInteger32_to_int()
            if Name == "OfflineAddressBookTruncatedProperties":
                val = hex(val)
                if val in PidTagSchema:
                    val = PidTagSchema[val]
            arr.append(val)
        return arr
    elif Type == "PtypMultipleBinary":
        byte_count = PtypInteger32_to_int()
        arr = []
        for j in range(byte_count):
            bin_len = PtypInteger32_to_int()
            bin_data = chunk.read(bin_len)
            arr.append(binascii.b2a_hex(bin_data).decode())
        return arr
    else:
        raise ValueError("Unknown property type (" + Type + ")")
        
def get_property_indices(rgHdrAtts):
    # A bit array that indicates whether a property specified in the
    # OAB_PROP_TABLE structure is present in the data field.
    # The size of the presenceBitArray field in bytes MUST be the
    # value of the cAtts field of the appropriate OAB_PROP_TABLE structure divided by 8 and
    # rounded up to the nearest integer value
    presenceBitArray = bytearray(chunk.read(int(math.ceil(rgHdrAtts / 8.0))))
    indices = [i for i in range(rgHdrAtts) if (presenceBitArray[i // 8] >> (7 - (i % 8))) & 1 == 1]
    return indices
    
def PtypString_to_str():
    # Strings in the OAB format are null-terminated
    buf = bytearray()
    while True:
        n = chunk.read(1)
        if n == b'\0' or n == b'':
            break
        buf.extend(n)
    return buf.decode(errors="ignore")

def PtypInteger32_to_int():
    # Integers equal to or less than 127 MUST be encoded as a
    # single byte. Integers 128 or greater are encoded with first a byte
    # count byte with the most significant bit set, then the
    # little-endian value encoding. The byte count, if required, 
    # MUST be 0x81, 0x82, # 0x83, or 0x84 representing 1, 2, 3, or 4 bytes. 
    byte_count = struct.unpack('<B', chunk.read(1))[0]
    if 0x81 <= byte_count <= 0x84:
        byte_count = struct.unpack('<I', (chunk.read(byte_count - 0x80) + b"\0\0\0")[0:4])[0]
    else:
        assert byte_count <= 127, "byte count must be <= 127"
    return byte_count
    
json_out = open('parsed_udetails.json', 'w')

# When reading a binary file, always add a 'b' to the file open mode
with open('udetails.oab', 'rb') as f:
    # First 3 bytes
    ulVersion, ulSerial, ulTotRecs = struct.unpack('<III', f.read(4 * 3))
    assert ulVersion == 32, 'This parser only supports an OAB Version 4 Details File'
    print(f"Flat OAB header version {ulVersion}, serial {hex(ulSerial)}, records {ulTotRecs}")
    print("------------------------")
    
    # Fourth byte is the size of the meta data chunk, which specifies which attributes are in the OAB header and data chunks
    cbSize = struct.unpack('<I', f.read(4))[0] # length of the OAB_META_DATA structure
    OAB_META_DATA = BytesIO(f.read(cbSize - 4))
    
    # The length of the header attributes inside OAB_META_DATA
    rgHdrAtts = struct.unpack('<I', OAB_META_DATA.read(4))[0]
    OAB_HDR_Atts = []
    # Get all header attributes that are present in the current OAB file
    for rgProp in range(rgHdrAtts):
        ulPropID, ulFlags = struct.unpack('<II', OAB_META_DATA.read(4 * 2))
        tagName = PidTagSchema[hex(ulPropID)]
        OAB_HDR_Atts.append((hex(ulPropID), ulFlags, tagName))
    
    print("Header Attributes")
    print("Property    Flags")
    print(f"cAtts = {rgHdrAtts}")
    for OAB_HDR_Att in OAB_HDR_Atts:
        print(f"{OAB_HDR_Att[0]}: {OAB_HDR_Att[1]}\t  {OAB_HDR_Att[2]}")
    print("------------------------")
    
    # The length of the data attributes inside OAB_META_DATA
    rgOabAtts = struct.unpack('<I', OAB_META_DATA.read(4))[0]
    OAB_Atts = []
    for rgProp in range(rgOabAtts):
        ulPropID, ulFlags = struct.unpack('<II', OAB_META_DATA.read(4 * 2))
        tagName = PidTagSchema[hex(ulPropID)]
        OAB_Atts.append((hex(ulPropID), ulFlags, tagName))

    print("OAB Attributes")
    print("Property    Flags")
    print(f"cAtts = {rgOabAtts}")
    for OAB_Att in OAB_Atts:
        print(f"{OAB_Att[0]}: {OAB_Att[1]}\t  {OAB_Att[2]}")
    print("------------------------")
    
    
    print("OAB Meta Data")
    # OAB_V4_REC (Header Properties)
    # The length of the OAB_V4_REC header
    cbSize = struct.unpack('<I', f.read(4))[0]
    
    # Parse the OAB_V4_REC header
    chunk = BytesIO(f.read(cbSize - 4))
    propertyIndices = get_property_indices(rgHdrAtts)
    for indice in propertyIndices:
        PropID = OAB_HDR_Atts[indice][0]
        Type = get_prop_type(PropID)
        Name = PidTagSchema[PropID]
        property_data = handle_property(Type)
        print(f"{PropID}: {property_data}")

    print("------------------------")
    print("")

    # Now parse the actual records
    for recordIndex in range(ulTotRecs):
        print("------------------------")
        print(f"Record {recordIndex}")
        print("------------------------")
        read = f.read(4)
              
        # This is the size of the chunk (one record), incidentally it's inclusive
        cbSize = struct.unpack('<I', read)[0]
        
        # So to read the rest, we subtract four
        chunk = BytesIO(f.read(cbSize - 4))
        propertyIndices = get_property_indices(rgOabAtts)

        record = {}
        for indice in propertyIndices:
            PropID = OAB_Atts[indice][0]
            Type = get_prop_type(PropID)
            Name = PidTagSchema[PropID]
            property_data = handle_property(Type)
            print(f"{PropID}: {property_data}")
            
            record[Name] = property_data

        remains = chunk.read()
        if len(remains) > 0:
            raise ValueError("This record contains unexpected data at the end: " + remains.decode())
                  
        json_out.write(json.dumps(record) + '\n')
