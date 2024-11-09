import struct

import ida_typeinf
from ida_hexrays import rlist_t
from ida_struct import get_struc_id,get_struc,\
    get_struc_size,get_member_name,get_member_tinfo

from VarViewer.dbg_stack import *
from VarViewer.dbg_func import VarInfo

CpuInfo.create_instance()
type_handlers = {
    ida_typeinf.BT_UNK: str,
    ida_typeinf.BT_VOID: str,
    ida_typeinf.BT_INT8: lambda b: int.from_bytes(b[:1], byteorder=CpuInfo.instance.endinness, signed=False),
    ida_typeinf.BT_INT16: lambda b: int.from_bytes(b[:2], byteorder=CpuInfo.instance.endinness, signed=False),
    ida_typeinf.BT_INT32: lambda b: int.from_bytes(b[:4], byteorder=CpuInfo.instance.endinness, signed=False),
    ida_typeinf.BT_INT64: lambda b: int.from_bytes(b[:8], byteorder=CpuInfo.instance.endinness, signed=False),
    ida_typeinf.BT_INT128: lambda b: int.from_bytes(b[:16], byteorder=CpuInfo.instance.endinness, signed=False),
    ida_typeinf.BT_INT: lambda b: int.from_bytes(b[:4], byteorder=CpuInfo.instance.endinness, signed=False),
    ida_typeinf.BT_BOOL: lambda b:  "True" if (b[0] != 0) else "False",
    ida_typeinf.BT_FLOAT: lambda b: struct.unpack('f', b[:4])[0] if(CpuInfo.instance.endinness == 'little') else struct.unpack('>f', b[:4])[0],
    ida_typeinf.BT_PTR: lambda b: int.from_bytes(b[:CpuInfo.instance.bitnessSize], byteorder=CpuInfo.instance.endinness, signed=False),
    ida_typeinf.BT_UNKNOWN: str,
    ida_typeinf.BT_UNK_BYTE: str,
    ida_typeinf.BT_UNK_WORD: str,
    ida_typeinf.BT_UNK_DWORD: str,
    ida_typeinf.BT_UNK_QWORD: str,
    ida_typeinf.BT_UNK_OWORD: str,
    ida_typeinf.BTF_BYTE: str,
    ida_typeinf.BTF_UNK: str,
    ida_typeinf.BTF_VOID: str,
    ida_typeinf.BTF_INT8: lambda b: int.from_bytes(b[:1], byteorder=CpuInfo.instance.endinness, signed=True),
    ida_typeinf.BTF_CHAR: lambda b: str(b[:1]),
    ida_typeinf.BTF_UINT8: lambda b: int.from_bytes(b[:1], byteorder=CpuInfo.instance.endinness, signed=False),
    ida_typeinf.BTF_INT16: lambda b: int.from_bytes(b[:2], byteorder=CpuInfo.instance.endinness, signed=True),
    ida_typeinf.BTF_UINT16: lambda b: int.from_bytes(b[:2], byteorder=CpuInfo.instance.endinness, signed=False),
    ida_typeinf.BTF_INT32: lambda b: int.from_bytes(b[:4], byteorder=CpuInfo.instance.endinness, signed=True),
    ida_typeinf.BTF_UINT32: lambda b: int.from_bytes(b[:4], byteorder=CpuInfo.instance.endinness, signed=False),
    ida_typeinf.BTF_INT64: lambda b: int.from_bytes(b[:8], byteorder=CpuInfo.instance.endinness, signed=True),
    ida_typeinf.BTF_UINT64: lambda b: int.from_bytes(b[:8], byteorder=CpuInfo.instance.endinness, signed=False),
    ida_typeinf.BTF_INT128: lambda b: int.from_bytes(b[:16], byteorder=CpuInfo.instance.endinness, signed=True),
    ida_typeinf.BTF_UINT128: lambda b: int.from_bytes(b[:16], byteorder=CpuInfo.instance.endinness, signed=False),
    ida_typeinf.BTF_INT: lambda b: int.from_bytes(b[:4], byteorder=CpuInfo.instance.endinness, signed=True),
    ida_typeinf.BTF_UINT: lambda b: int.from_bytes(b[:4], byteorder=CpuInfo.instance.endinness, signed=False),
    ida_typeinf.BTF_SINT: lambda b: int.from_bytes(b[:4], byteorder=CpuInfo.instance.endinness, signed=True),
    ida_typeinf.BTF_BOOL: lambda b:  "True" if (b[0] != 0) else "False",
    ida_typeinf.BTF_FLOAT: lambda b: struct.unpack('f', b[:4])[0] if(CpuInfo.instance.endinness == 'little') else struct.unpack('>f', b[:4])[0],
    ida_typeinf.BTF_DOUBLE: lambda b: struct.unpack('d', b[:8])[0] if(CpuInfo.instance.endinness == 'little') else struct.unpack('>d', b[:8])[0],
    ida_typeinf.BTF_LDOUBLE: lambda b: struct.unpack('d', b[:8])[0] if(CpuInfo.instance.endinness == 'little') else struct.unpack('>d', b[:8])[0],
    ida_typeinf.BTF_TBYTE: lambda _: "tbyte",
    ida_typeinf.BTF_STRUCT: lambda _: "struct",
    ida_typeinf.BTF_UNION: lambda _: "union",
    ida_typeinf.BTF_ENUM: lambda _: "enum",
    ida_typeinf.BTF_TYPEDEF: lambda _: "typedef"
}



def GetRegName(reg,width):
    '''
    reg: mreg_t  width: int   return: str
    Get the register name according to mreg_t and width
    '''
    rlist = rlist_t(reg,width)
    regname = rlist.dstr()
    return regname

def GetTypeName(struct_):
    '''struct: <class 'ida_typeinf.tinfo_t'>   return: str'''
    return struct_.dstr()

def ConversionBytesToStr(byte,size,type_):
    '''conversion bytes to string according to typeinfo'''
    if not (type_.is_array() or type_.is_ptr() or type_.is_struct()):
        real_type = type_.get_realtype()
        byte = byte[:size]
        if real_type in type_handlers:
            handler = type_handlers.get(real_type, str)
            result =  handler(byte)
        else:
            result = str(byte)
        if isinstance(result, str):
            return result
        else:
            return str(result)
    elif type_.is_array():
        elem_type,elem_nelems = GetArrayElemInfo(type_)
        elem_size = elem_type.get_size()
        result = []
        for i in range(elem_nelems):
            elem_bytes = byte[i*elem_size : (i+1)*elem_size+1]
            result.append(ConversionBytesToStr(elem_bytes,elem_size,elem_type))
        return "[" + ",".join(result) + "]"
    elif type_.is_ptr():
        value = int.from_bytes(byte[0:CpuInfo.instance.bitnessSize],byteorder=CpuInfo.instance.endinness)
        if idc.is_loaded(value):
            target_type,target_size = GetPtrTargetInfo(type_)
            if target_size == -1:
                return f"{value:X}"
            target_bytes = idc.get_bytes(value,target_size)
            result = ConversionBytesToStr(target_bytes,target_size,target_type)
            return f"{value:X}{ARROW_SYMBOL}{result}"
        else:
            return f"{value:X}"

    elif type_.is_struct():
        struct_members = GetStructMembersInfo(type_)
        result = []
        for member in struct_members:
            member_name = member.name
            member_type = member.type
            member_size = member.size
            member_soff = member.addr
            member_bytes = byte[member_soff : member_soff+member_size]
            result.append(f"{member_name}:{ConversionBytesToStr(member_bytes, member_size, member_type)}")
        return "{" + ",".join(result) + "}"



def GetArrayElemInfo(type_):
    '''struct: <class 'ida_typeinf.tinfo_t'>   return: [<class 'tinfo_t'>,<num of elements>]'''
    arr_type = ida_typeinf.array_type_data_t()
    type_.get_array_details(arr_type)
    return arr_type.elem_type,arr_type.nelems

def GetPtrTargetInfo(type_):
    '''struct: <class 'ida_typeinf.tinfo_t'>   return: [<class 'tinfo_t'>,<size of target>]'''
    target_type = type_.get_ptrarr_object()
    target_size = type_.get_ptrarr_objsize()
    return target_type,target_size

def GetStructSizeInfo(type_):
    '''struct: <class 'ida_typeinf.tinfo_t'>   return: <size of struct>'''
    typename = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, type_, '', '')
    struct_id = get_struc_id(typename)
    struct_ptr = get_struc(struct_id)
    return get_struc_size(struct_ptr)

def GetStructMembersInfo(type_):
    '''struct: <class 'ida_typeinf.tinfo_t'>   return: member information list'''
    typename = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, type_, '', '')
    struct_id = get_struc_id(typename)
    if struct_id is None:
        return []
    struct_ptr = get_struc(struct_id)
    if struct_ptr is None:
        return []
    member_num = struct_ptr.members.count

    # members info: [name, type, soff, size]
    struct_members = []
    for i in range(member_num):
        member = struct_ptr.members[i]

        member_name = get_member_name(member.id)
        member_type =  ida_typeinf.tinfo_t()
        get_member_tinfo(member_type,member)

        member_soff = member.soff
        member_eoff = member.eoff
        member_size = member_eoff - member_soff

        struct_members.append(VarInfo(member_name,member_size,member_soff,member_type))

    return struct_members
