import ida_typeinf
import ida_hexrays

from StackView.DbgStackInspector import *
from StackView.Dbg_Hooks import *


import struct


TypeDict = {
    ida_typeinf.BT_UNK: "unk",
    ida_typeinf.BT_VOID: "void",
    ida_typeinf.BT_INT8: "__int8",
    ida_typeinf.BT_INT16: "__int16",
    ida_typeinf.BT_INT32: "__int32",
    ida_typeinf.BT_INT64: "__int64",
    ida_typeinf.BT_INT128: "__int128",
    ida_typeinf.BT_INT: "int",
    ida_typeinf.BT_BOOL: "bool",
    ida_typeinf.BT_FLOAT: "float",
    ida_typeinf.BT_PTR: "pointer",
    ida_typeinf.BT_ARRAY: "array", 
    ida_typeinf.BT_UNK_BYTE: "1 byte",
    ida_typeinf.BT_UNK_WORD: "2 bytes",
    ida_typeinf.BT_UNK_DWORD: "4 bytes",
    ida_typeinf.BT_UNK_QWORD: "8 bytes",
    ida_typeinf.BT_UNK_OWORD: "16 bytes",
    ida_typeinf.BT_UNKNOWN: "unknown size",
    ida_typeinf.BT_SEGREG: "segment register",  
    ida_typeinf.BT_UNK_BYTE: "1 byte",
    ida_typeinf.BT_UNK_WORD: "2 bytes",
    ida_typeinf.BT_UNK_DWORD: "4 bytes",
    ida_typeinf.BT_UNK_QWORD: "8 bytes",
    ida_typeinf.BT_UNK_OWORD: "16 bytes",
    ida_typeinf.BT_UNKNOWN: "unknown size - for parameters", 
    ida_typeinf.BTF_BYTE: "byte",
    ida_typeinf.BTF_UNK: "unknown", 
    ida_typeinf.BTF_VOID: "void",  
    ida_typeinf.BTF_INT8: "int8",
    ida_typeinf.BTF_CHAR: "char",
    ida_typeinf.BTF_UCHAR: "unsigned char", 
    ida_typeinf.BTF_UINT8: "uint8",
    ida_typeinf.BTF_INT16: "int16",
    ida_typeinf.BTF_UINT16: "uint16",
    ida_typeinf.BTF_INT32: "int32",
    ida_typeinf.BTF_UINT32: "uint32",
    ida_typeinf.BTF_INT64: "int64",
    ida_typeinf.BTF_UINT64: "uint64",
    ida_typeinf.BTF_INT128: "int128",   
    ida_typeinf.BTF_UINT128: "uint128", 
    ida_typeinf.BTF_INT: "int",
    ida_typeinf.BTF_UINT: "uint",
    ida_typeinf.BTF_SINT: "sint",
    ida_typeinf.BTF_BOOL: "bool",
    ida_typeinf.BTF_FLOAT: "float",
    ida_typeinf.BTF_DOUBLE: "double",
    ida_typeinf.BTF_LDOUBLE: "long double", 
    ida_typeinf.BTF_TBYTE: "tbyte",   
    ida_typeinf.BTF_STRUCT: "struct",
    ida_typeinf.BTF_UNION: "union",
    ida_typeinf.BTF_ENUM: "enum",
    ida_typeinf.BTF_TYPEDEF: "typedef",
}



type_handlers = {
    ida_typeinf.BT_UNK: lambda b: str(b), 
    ida_typeinf.BT_VOID: lambda b: str(b), 
    ida_typeinf.BT_INT8: lambda b: int.from_bytes(b[:1], byteorder=CPUinfo.endinness, signed=False),
    ida_typeinf.BT_INT16: lambda b: int.from_bytes(b[:2], byteorder=CPUinfo.endinness, signed=False),
    ida_typeinf.BT_INT32: lambda b: int.from_bytes(b[:4], byteorder=CPUinfo.endinness, signed=False),
    ida_typeinf.BT_INT64: lambda b: int.from_bytes(b[:8], byteorder=CPUinfo.endinness, signed=False),
    ida_typeinf.BT_INT128: lambda b: int.from_bytes(b[:16], byteorder=CPUinfo.endinness, signed=False),
    ida_typeinf.BT_INT: lambda b: int.from_bytes(b[:4], byteorder=CPUinfo.endinness, signed=False),
    ida_typeinf.BT_BOOL: lambda b:  "True" if (b[0] != 0) else "False",
    ida_typeinf.BT_FLOAT: lambda b: struct.unpack('f', b[:4])[0] if(CPUinfo.endinness == 'little') else struct.unpack('>f', b[:4])[0],
    ida_typeinf.BT_PTR: lambda b: int.from_bytes(b[:CPUinfo.bitnessSize], byteorder=CPUinfo.endinness, signed=False),
    ida_typeinf.BT_UNKNOWN: lambda b: str(b), 
    ida_typeinf.BT_UNK_BYTE: lambda b: str(b), 
    ida_typeinf.BT_UNK_WORD: lambda b: str(b), 
    ida_typeinf.BT_UNK_DWORD: lambda b: str(b), 
    ida_typeinf.BT_UNK_QWORD: lambda b: str(b), 
    ida_typeinf.BT_UNK_OWORD: lambda b: str(b), 
    ida_typeinf.BT_UNK_BYTE: lambda b: str(b),
    ida_typeinf.BT_UNK_WORD: lambda b: str(b),
    ida_typeinf.BT_UNK_DWORD: lambda b: str(b),
    ida_typeinf.BT_UNK_QWORD: lambda b: str(b),
    ida_typeinf.BT_UNK_OWORD: lambda b: str(b),
    ida_typeinf.BT_UNKNOWN: lambda b: str(b),
    ida_typeinf.BTF_BYTE: lambda b: str(b),
    ida_typeinf.BTF_UNK: lambda b: str(b),
    ida_typeinf.BTF_VOID: lambda b: str(b),  
    ida_typeinf.BTF_INT8: lambda b: int.from_bytes(b[:1], byteorder=CPUinfo.endinness, signed=True),
    ida_typeinf.BTF_CHAR: lambda b: str(b[:1]),
    ida_typeinf.BTF_UINT8: lambda b: int.from_bytes(b[:1], byteorder=CPUinfo.endinness, signed=False),
    ida_typeinf.BTF_INT16: lambda b: int.from_bytes(b[:2], byteorder=CPUinfo.endinness, signed=True),
    ida_typeinf.BTF_UINT16: lambda b: int.from_bytes(b[:2], byteorder=CPUinfo.endinness, signed=False),
    ida_typeinf.BTF_INT32: lambda b: int.from_bytes(b[:4], byteorder=CPUinfo.endinness, signed=True),
    ida_typeinf.BTF_UINT32: lambda b: int.from_bytes(b[:4], byteorder=CPUinfo.endinness, signed=False),
    ida_typeinf.BTF_INT64: lambda b: int.from_bytes(b[:8], byteorder=CPUinfo.endinness, signed=True),
    ida_typeinf.BTF_UINT64: lambda b: int.from_bytes(b[:8], byteorder=CPUinfo.endinness, signed=False),
    ida_typeinf.BTF_INT128: lambda b: int.from_bytes(b[:16], byteorder=CPUinfo.endinness, signed=True),
    ida_typeinf.BTF_UINT128: lambda b: int.from_bytes(b[:16], byteorder=CPUinfo.endinness, signed=False),
    ida_typeinf.BTF_INT: lambda b: int.from_bytes(b[:4], byteorder=CPUinfo.endinness, signed=True),
    ida_typeinf.BTF_UINT: lambda b: int.from_bytes(b[:4], byteorder=CPUinfo.endinness, signed=False),
    ida_typeinf.BTF_SINT: lambda b: int.from_bytes(b[:4], byteorder=CPUinfo.endinness, signed=True),
    ida_typeinf.BTF_BOOL: lambda b:  "True" if (b[0] != 0) else "False",
    ida_typeinf.BTF_FLOAT: lambda b: struct.unpack('f', b[:4])[0] if(CPUinfo.endinness == 'little') else struct.unpack('>f', b[:4])[0],
    ida_typeinf.BTF_DOUBLE: lambda b: struct.unpack('d', b[:8])[0] if(CPUinfo.endinness == 'little') else struct.unpack('>d', b[:8])[0],
    ida_typeinf.BTF_LDOUBLE: lambda b: struct.unpack('d', b[:8])[0] if(CPUinfo.endinness == 'little') else struct.unpack('>d', b[:8])[0],
    ida_typeinf.BTF_TBYTE: lambda _: "tbyte",
    ida_typeinf.BTF_STRUCT: lambda _: "struct",
    ida_typeinf.BTF_UNION: lambda _: "union",
    ida_typeinf.BTF_ENUM: lambda _: "enum",
    ida_typeinf.BTF_TYPEDEF: lambda _: "typedef"
}


# reg: mreg_t  width: int   return: str
# 按照mreg_t和长度得到寄存器名称
def GetRegName(reg,width):
    rlist = ida_hexrays.rlist_t(reg,width)
    regname = rlist.dstr()
    return regname


# struct: <class 'ida_typeinf.tinfo_t'>   return: str 
def GetSturctName(struct):
    return struct.__str__()
    


def ConversionByteToStr(byte,size,type):
    real_type = type.get_realtype()
    byte = byte[:size]  
    if(real_type in type_handlers.keys()):
        handler = type_handlers.get(real_type, lambda b: str(b))  # 默认情况
        result =  handler(byte)
    else:
        result = str(byte)
    if(isinstance(result, str)):
        return result
    else:
        return str(result)



def GetArrayElemInfo(type):
    arr_type = ida_typeinf.array_type_data_t()
    type.get_array_details(arr_type)
    return arr_type.elem_type,arr_type.nelems



def GetPtrTargetInfo(type):
    target_type = type.get_ptrarr_object()
    target_size = type.get_ptrarr_objsize()
    return target_type,target_size




def GetStructSizeInfo(type):
    typename = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, type, '', '')
    struct_id = ida_struct.get_struc_id(typename)
    struct_ptr = ida_struct.get_struc(struct_id)
    return ida_struct.get_struc_size(struct_ptr)


def GetStructMemberInfo(type):
    typename = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, type, '', '')
    struct_id = ida_struct.get_struc_id(typename)
    struct_ptr = ida_struct.get_struc(struct_id)


    member_num = struct_ptr.members.count

    struct_members = []

    for i in range(member_num):
        member = struct_ptr.members[i]

        member_name = ida_struct.get_member_name(member.id)
        member_type =  ida_typeinf.tinfo_t()
        ida_struct.get_member_tinfo(member_type,member)

        member_soff = member.soff
        member_eoff = member.eoff
        member_size = member_eoff - member_soff


        struct_members.append([member_name,member_type,member_soff,member_size])

    return struct_members