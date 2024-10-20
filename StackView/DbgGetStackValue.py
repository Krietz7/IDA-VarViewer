import idaapi
import idc
import ida_idaapi


# 获取CPU
class CpuInfo():
    stack_registers = {
        "x86":{
            "BasePointer": "EBP",
            "StackPointer": "ESP"
        },
        "x64":{
            "BasePointer": "RBP",
            "StackPointer": "RSP"
        }
    }


    def __init__(self):
        procname = self.get_structure()
        bitness = self.get_bitness()
        if(procname == "metapc"):
            self.cpu_struct =  {32:"x86",64:"x64"}[bitness]

    @staticmethod
    def GetCpuInfo():
        procname =  CpuInfo().get_structure()
        bitness = CpuInfo().get_bitness()
        if(procname == "metapc"):
            return {32:"x86",64:"x64"}[bitness]
        else:
            return None

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
            









# 获取调试时的栈信息
class DbgGetStackValue():
    def __init__(self):
        self.cpu_info = CpuInfo()
        self.stack_registers = self.cpu_info.stack_registers[self.cpu_info.cpu_struct]
        
        self.base_pointer = self.stack_registers["BasePointer"]
        self.stack_pointer = self.stack_registers["StackPointer"]



    def GetDbgStatus(self):
        return idaapi.is_debugger_on()


    # 获取栈指针的值
    def GetStackValue(self):
        if(idaapi.is_debugger_on()):
            self.base_pointer_value = idaapi.get_reg_val(self.base_pointer)
            self.stack_pointer_value = idaapi.get_reg_val(self.stack_pointer)

            return self.base_pointer_value,self.stack_pointer_value
        else:
            print("Not in debuging")
            return None


    

























