import idaapi,idc,ida_nalt,ida_bytes,ida_struct,ida_name

from StackView.Defines import *





# 获取CPU
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
        self.is_bigendianness = self.get_endianness()
        if(self.procname == "metapc"):
            self.cpu_struct =  {32:"x86",64:"x64"}[self.bitness]

        if(not self.is_bigendianness):
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
        elif idaapi.get_inf_structure().is_32bit():
            return 32
        else:
            idaapi.warnings("Not supported bitness")
            return None
            


    @staticmethod
    def get_endianness():
        return idaapi.get_inf_structure().is_be()






SEC_cpu_info = CpuInfo()



# 获取栈寄存器名称
def GetStackRegsName():
    global SEC_cpu_info
    stack_registers = SEC_cpu_info.stack_registers[SEC_cpu_info.cpu_struct]
    
    base_pointer = stack_registers["BasePointer"]
    stack_pointer = stack_registers["StackPointer"]
    two_pointer = stack_registers["TwoPointer"]
    instruction_pointer = stack_registers["InstructionPointer"]
    return  base_pointer,stack_pointer,two_pointer,instruction_pointer


# 获取调试状态
def GetDbgStatus():
    return idaapi.is_debugger_on()


# 获取栈指针的值
def GetStackValue():
    if(idaapi.is_debugger_on()):
        base_pointer, stack_pointer,two_pointer,InstructionPointer = GetStackRegsName()
        
        try:
            base_pointer_value = idaapi.get_reg_val(base_pointer)
            stack_pointer_value = idaapi.get_reg_val(stack_pointer)

            return base_pointer_value,stack_pointer_value
        except:
            return None

    else:
        print("Not in debuging")
        return None





# 判断值类型 指针 / 变量

def addressSegmentType(Address):
    # 指针指向： 栈地址 指令 外部调用 下一个指针
    if idaapi.is_loaded(Address):
        segm = idaapi.getseg(Address)
        return idaapi.get_segm_class(segm),idaapi.get_segm_name(segm,0)
    else:
        return None





def NumberConversion(type,data_bytes,endinness):
    Number_array = []
    type_len_list = {"Byte":1,"Word":2,"Dword":4,"Qword":8}
    Number_len = type_len_list[type]
    base = 16
    if(endinness == "little"):
        for i in range(0, len(data_bytes), Number_len):
            Number_array.append(int.from_bytes(data_bytes[i:i+Number_len],byteorder='little'))
    else:
        for i in range(0, len(data_bytes), Number_len):
            Number_array.append(int.from_bytes(data_bytes[i:i+Number_len],byteorder='big'))
    return ",".join("{0}".format(hex(i)) for i in Number_array)




def GetDataDescription(address,endinness,pointing_value = None):
    data_size = idc.get_item_size(address)
    data_value = idc.get_bytes(address, data_size)
    data_type_flag = ida_bytes.get_flags(address)


    suffix = ""
    if(data_size > MAX_DATA_DISPLAY_SIZE):
        data_value = data_value[0:MAX_DATA_DISPLAY_SIZE]
        suffix = "..."





    result = ""
    # if(idc.get_name(address) not in [None,""] ):
    #     result += idc.get_name(address) + ": "

    

    # string
    if(idc.is_strlit(data_type_flag) or idc.get_strlit_contents(address) != None):
        return result + "("+str(idc.get_strlit_contents(address))+")"  
    
    # type
    elif(idc.is_byte(data_type_flag)):
        if(data_size == 1):
            return result + NumberConversion("Byte",data_value,endinness)
        elif(data_size > 1):
             return result + "[" + NumberConversion("Byte",data_value,endinness) + suffix + "]"
    
    elif(idc.is_word(data_type_flag)):
        if(data_size == 2):
            return result + NumberConversion("Word",data_value,endinness)
        elif(data_size > 2):
             return result + "[" + NumberConversion("Word",data_value,endinness) + suffix + "]"
    
    elif(idc.is_dword(data_type_flag)):
        if(data_size == 4):
            return result + NumberConversion("Word",data_value,endinness)
        elif(data_size > 4):
            return result + "[" + NumberConversion("Dword",data_value,endinness) + suffix + "]"
     
    elif(idc.is_qword(data_type_flag)):
        if(data_size == 8):
            return result + NumberConversion("Word",data_value,endinness)
        elif(data_size > 8):
            return result + "[" + NumberConversion("Qword",data_value,endinness) + suffix + "]"

    elif(idc.is_struct(data_type_flag)):
        buf = ida_nalt.opinfo_t()
        flags = ida_bytes.get_flags(address)
        opi = ida_bytes.get_opinfo(buf, address, 0, flags)
        if(opi != None):
            struct = ida_struct.get_struc(opi.tid)
            if(ida_struct.get_struc_name(opi.tid) != None):
                result += "STRUCT " + ida_struct.get_struc_name(opi.tid)
        
        else:
            result += "Unknown Struct "
        return result + " " + hex(address)


    elif(idc.is_align(data_type_flag)):
        return result + "Alignment Padding"





    elif(idc.is_unknown(data_type_flag) and pointing_value != None):
        return pointing_value






    else:
        if(data_size > MAX_DATA_DISPLAY_SIZE):
            return result + str(data_value[0:MAX_DATA_DISPLAY_SIZE]) + suffix
        else:
            return result + str(data_value)





def GetValueDescription(value, processed_addresses=None):
    if processed_addresses is None:
        processed_addresses = set()

    result = []
    global SEC_cpu_info
    if SEC_cpu_info.bitness == 32:
        pointer_size = 4
    elif SEC_cpu_info.bitness == 64:
        pointer_size = 8
    else:
        return []
    
    if (pointer_size == 4):
        pointer_format_str = "{:0>8X}"
    elif (pointer_size == 8):
        pointer_format_str = "{:0>16X}"
    else:
        return []



    if(not SEC_cpu_info.is_bigendianness):
        endinness = 'little'
    else:
        endinness = 'big'

    # 是指针
    if idaapi.is_loaded(value) and value not in processed_addresses:
        processed_addresses.add(value)
        
        segm_type,segm_name = addressSegmentType(value)
        value_name =     ida_name.get_nice_colored_name(value,ida_name.GNCN_NOCOLOR)

        pointing_value = int.from_bytes(idc.get_bytes(value, pointer_size), byteorder=endinness)
        pointer_format = pointer_format_str.format(pointing_value)

        is_address = idaapi.is_loaded(pointing_value)



        if(segm_type == None):
            return [[0,"",""]]
        
        elif(segm_type == "CODE"):
            result.append([T_CODE, value_name, idc.GetDisasm(value)])

        elif(segm_type == "DATA"):
            if(is_address):
                result.append([T_DATA, value_name, pointer_format])
            else:
                result.append([T_DATA, value_name, GetDataDescription(value,endinness,pointer_format)])


        elif(segm_type == "STACK"):
            if(is_address):
                result.append([T_STACK, value_name, pointer_format])
            else:
                result.append([T_STACK, value_name, GetDataDescription(value,endinness,pointer_format)])



        elif(segm_type == "BSS"):
            if(is_address):
                result.append([T_BSS, value_name, pointer_format])
            else:
                result.append([T_BSS, value_name, GetDataDescription(value,endinness,pointer_format)])

        elif(segm_type == "CONST"):
            if(is_address):
                result.append([T_CONST, value_name, pointer_format])
            else:
                result.append([T_CONST, value_name, GetDataDescription(value,endinness,pointer_format)])

        if is_address and pointing_value not in processed_addresses:
            result += GetValueDescription(pointing_value, processed_addresses)


        return result
    else:
        return [[0,"",""]]






































