import idaapi,idc
from ida_nalt import opinfo_t
from ida_bytes import get_flags,get_opinfo
from ida_struct import get_struc_name
from ida_name import get_nice_colored_name,GNCN_NOCOLOR

from VarViewer.config import *

T_VALUE = 0
T_CODE = 1
T_DATA = 2
T_STACK = 3
T_BSS = 4
T_CONST = 5



# get CPU info
class CpuInfo():
    stack_registers = {
        "x86":{
            "BasePointer": "EBP",
            "StackPointer": "ESP",
            "TwoPointer": "BPSP",
            "InstructionPointer":"EIP"
        },
        "x64":{
            "BasePointer": "RBP",
            "StackPointer": "RSP",
            "TwoPointer": "BPSP",
            "InstructionPointer":"RIP"

        }
    }

    def __init__(self):
        self.procname = self.get_structure()
        self.bitness = self.get_bitness()
        self.bitnessSize = self.bitness // 8
        self.is_bigendianness = self.get_endianness()
        if self.procname == "metapc":
            self.cpu_struct =  {32:"x86",64:"x64"}[self.bitness]

        if not self.is_bigendianness:
            self.endinness = 'little'
        else:
            self.endinness = 'big'



    @staticmethod
    def get_structure():
        return idaapi.get_inf_structure().procname.lower()


    @staticmethod
    def get_bitness():
        if idaapi.get_inf_structure().is_64bit():
            return 64
        if idaapi.get_inf_structure().is_32bit():
            return 32
        return None

    @staticmethod
    def get_endianness():
        return idaapi.get_inf_structure().is_be()

CPUinfo = CpuInfo()



class StackVarRemark():
    def __init__(self,stkvar_base_addr,remark_text,remark_color,var_info_list):
        self.base_addr = stkvar_base_addr
        self.remark_text = remark_text
        self.remark_color = remark_color
        self.VarInfoList = var_info_list
        self.description_text = None










def GetStackRegsName():
    stack_registers = CPUinfo.stack_registers[CPUinfo.cpu_struct]

    base_pointer = stack_registers["BasePointer"]
    stack_pointer = stack_registers["StackPointer"]
    two_pointer = stack_registers["TwoPointer"]
    instruction_pointer = stack_registers["InstructionPointer"]
    return  base_pointer,stack_pointer,two_pointer,instruction_pointer


def GetDbgStatus():
    return idaapi.is_debugger_on()


def GetStackValue():
    if idaapi.is_debugger_on():
        base_pointer, stack_pointer, _,_ = GetStackRegsName()

        try:
            base_pointer_value = idaapi.get_reg_val(base_pointer)
            stack_pointer_value = idaapi.get_reg_val(stack_pointer)

            return base_pointer_value,stack_pointer_value
        except Exception:
            return None,None

    else:
        return None

def GetSegmentType(Address):
    if idaapi.is_loaded(Address):
        segm = idaapi.getseg(Address)
        if segm is not None:
            return idaapi.get_segm_class(segm),idaapi.get_segm_name(segm,0)
    return None,None



def NumberConversion(type_,data_bytes,endinness):
    Number_array = []
    type_len_list = {"Byte":1,"Word":2,"Dword":4,"Qword":8}
    Number_len = type_len_list[type_]

    if endinness == "little":
        for i in range(0, len(data_bytes), Number_len):
            Number_array.append(int.from_bytes(data_bytes[i:i+Number_len],byteorder='little'))
    else:
        for i in range(0, len(data_bytes), Number_len):
            Number_array.append(int.from_bytes(data_bytes[i:i+Number_len],byteorder='big'))
    return ",".join(f"{i:X}" for i in Number_array)


def GetDataDescription(address,endinness,pointing_value = None):
    data_size = idc.get_item_size(address)
    data_value = idc.get_bytes(address, data_size)
    data_type_flag = get_flags(address)

    suffix = ""
    result = ""

    # convert the value at the address to a string
    # string
    if(idc.is_strlit(data_type_flag) or\
            (idc.get_strlit_contents(address) is not None\
            and len(idc.get_strlit_contents(address)) > 4)):
        return result + "("+str(idc.get_strlit_contents(address))+")"

    # type
    elif idc.is_byte(data_type_flag):
        if data_size == 1:
            return result + NumberConversion("Byte",data_value,endinness)
        elif data_size > 1:
            return result + "[" + NumberConversion("Byte",data_value,endinness) + suffix + "]"
    elif idc.is_word(data_type_flag):
        if data_size == 2:
            return result + NumberConversion("Word",data_value,endinness)
        elif data_size > 2:
            return result + "[" + NumberConversion("Word",data_value,endinness) + suffix + "]"
    elif idc.is_dword(data_type_flag):
        if data_size == 4:
            return result + NumberConversion("Dword",data_value,endinness)
        elif data_size > 4:
            return result + "[" + NumberConversion("Dword",data_value,endinness) + suffix + "]"
    elif idc.is_qword(data_type_flag):
        if data_size == 8:
            return result + NumberConversion("Qword",data_value,endinness)
        elif data_size > 8:
            return result + "[" + NumberConversion("Qword",data_value,endinness) + suffix + "]"

    # struct
    elif idc.is_struct(data_type_flag):
        buf = opinfo_t()
        flags = get_flags(address)
        opi = get_opinfo(buf, address, 0, flags)
        if opi is not None:
            if get_struc_name(opi.tid) is not None:
                result += "STRUCT " + get_struc_name(opi.tid)
        else:
            result += "Unknown Struct "
        return result + f" {address:X}"

    # padding
    elif idc.is_align(data_type_flag):
        return result + "Alignment Padding"

    # unknown
    else:
        return pointing_value


def GetValueDescription(value, processed_addresses=None):
    '''
    a stack frame usually contains a address or data
    the func used to find the address it points to and use different flag to mark it
    or descripte the data it stores
    '''
    if processed_addresses is None:
        processed_addresses = set()

    result = []
    if CPUinfo.bitness == 32:
        pointer_size = 4
    elif CPUinfo.bitness == 64:
        pointer_size = 8
    else:
        return []

    if pointer_size == 4:
        pointer_format_str = "{:0>8X}"
    elif pointer_size == 8:
        pointer_format_str = "{:0>16X}"
    else:
        return []

    if not CPUinfo.is_bigendianness:
        endinness = 'little'
    else:
        endinness = 'big'

    if(idaapi.is_loaded(value) and value not in processed_addresses):
        processed_addresses.add(value)

        segm_type,_ = GetSegmentType(value)
        value_name = get_nice_colored_name(value,GNCN_NOCOLOR)

        pointing_value = int.from_bytes(idc.get_bytes(value, pointer_size), byteorder=endinness)
        pointer_str = pointer_format_str.format(pointing_value)

        is_address = idaapi.is_loaded(pointing_value)

        if segm_type is None:
            return [[0,"","",value]]

        elif segm_type == "CODE":
            result.append([T_CODE, value_name, idc.GetDisasm(value), value])

        elif segm_type == "DATA":
            if is_address:
                result.append([T_DATA, value_name, pointer_str, value])
            else:
                result.append([T_DATA, value_name, GetDataDescription(value,endinness,pointer_str), value])

        elif segm_type == "STACK":
            if is_address:
                result.append([T_STACK, value_name, pointer_str, value])
            else:
                result.append([T_STACK, value_name, GetDataDescription(value,endinness,pointer_str), value])

        elif segm_type == "BSS":
            if is_address:
                result.append([T_BSS, value_name, pointer_str, value])
            else:
                result.append([T_BSS, value_name, GetDataDescription(value,endinness,pointer_str), value])

        elif segm_type == "CONST":
            if is_address:
                result.append([T_CONST, value_name, pointer_str, value])
            else:
                result.append([T_CONST, value_name, GetDataDescription(value,endinness,pointer_str), value])

        if is_address and pointing_value not in processed_addresses:
            result += GetValueDescription(pointing_value, processed_addresses)

        # return: a list of the values descriptions
        # if the value is another address, record its description information in the next item in the list
        return result
    return [[0,"","",value]]
