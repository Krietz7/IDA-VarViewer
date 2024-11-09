from idaapi import get_reg_val
from idc import get_bytes,find_code
from ida_funcs import FUNC_FRAME,FUNC_FUZZY_SP,get_fchunk
from ida_frame import frame_off_retaddr
from ida_struct import get_struc,get_member_name,get_member_tinfo
from ida_dbg import get_current_thread,collect_stack_trace
from ida_idd import call_stack_t
from ida_hexrays import decompile
from ida_typeinf import tinfo_t


from VarViewer.config import *
from VarViewer.dbg_stack import *

class VarInfo():
    def __init__(self, var_name, var_size, var_addr, var_type, var_value = None):
        self.name = var_name
        self.size = var_size
        self.addr = var_addr
        self.type = var_type
        self.value = var_value





def GetFrameBaseAddress(func, ip_reg_value, sp_reg_value, bitness, endinness, trace_depth = 0):
    '''
    Get the top address of the stack after executing the call instruction as the base address
    return : frame base address
    '''
    pointer_size = bitness // 8

    if func is None:
        return None
    func_flags = func.flags

    func_base_addr = sp_reg_value
    frame = func.frame

    # Analysis start conditions:
    # Stack frame analysis is complete.
    # The stack frame uses the stack base register.
    # There is no special stack frame usage.
    if ((not (func_flags & FUNC_FRAME) or  ( func_flags & FUNC_FUZZY_SP)) and (CHECK_FUNC_FLAG_BEFORE_TRACE)):
        return None


    # Base address search method:
    # Use the return address obtained from the stack trace to search from the top of the stack downwards

    # Find the base address through func.points
    for i in range(func.points.count):
        stkpnt = func.points[i]
        if stkpnt.ea > ip_reg_value:
            break

        func_base_addr = sp_reg_value - stkpnt.spd

    # Finding the base address by calling stack trace
    tid =  get_current_thread()
    trace = call_stack_t()
    return_ea = None
    return_ea_next_addr = None
    if (collect_stack_trace(tid, trace) and len(trace) > trace_depth):
        frame = trace[trace_depth + 1]
        return_ea = frame.callea
        return_ea_next_addr =  find_code(return_ea,1)

    # Check if the next address of the base address is the return address
    if return_ea is not None:
        addr_bytes = get_bytes(func_base_addr,pointer_size)
        addr_int =  int.from_bytes(addr_bytes, byteorder = endinness)
        if addr_int in [return_ea,return_ea_next_addr]:
            return func_base_addr
    return None


def GetStkVar(func,func_base_addr,bitnessSize):
    '''
    Get all stack variables by func object and its base address
    return: a dist of variables info, use address as key
    '''
    stkvar_dict = {}
    frame = func.frame
    struct_ptr = get_struc(frame)
    lvar_base_addr = frame_off_retaddr(func)

    if struct_ptr is not None:
        if struct_ptr.is_frame():
            for mptr in struct_ptr.members:
                name = get_member_name(mptr.id)
                size = mptr.get_size()
                offset = mptr.soff
                mtype = tinfo_t()
                get_member_tinfo(mtype,mptr)

                addr = (func_base_addr - lvar_base_addr + offset) - (func_base_addr - lvar_base_addr + offset) % bitnessSize
                if addr not in stkvar_dict:
                    stkvar_dict[addr] = [VarInfo(name, size, func_base_addr - lvar_base_addr + offset, mtype)]
                else:
                    stkvar_dict[addr] += [VarInfo(name, size, func_base_addr - lvar_base_addr + offset, mtype)]
    # return : dict { address : [VarInfo, VarInfo, ...]}
    return stkvar_dict


def GetFuncLocationVar(func):
    '''
    Get all local variables and its location according to the func object
    return : Three lists storing three types of local variables
    '''
    cfunc = decompile(func)
    lvars = cfunc.lvars

    stk_var_list = []
    reg1_var_list = []
    reg2_var_list = []

    for var in lvars:
        if var.used:
            var_name = var.name
            var_size = var.width
            var_type = var.tif

            # This variable is a stack variable.
            if(var.is_stk_var and var.get_stkoff() > 0 ):
                off = var.get_stkoff()
                stk_var_list.append(VarInfo(var_name, var_size, off, var_type))

            # This variable is a register variable.
            elif var.is_reg_var:
                # This variable stored in a single register
                if(var.is_reg1 and var.get_reg2() == 0):
                    Reg1 = var.get_reg1() # mreg_t
                    reg1_var_list.append(VarInfo(var_name, var_size, Reg1, var_type))


                # This variable stored in Two registers
                elif(var.is_reg2 and var.get_reg2() != 0):
                    Reg1 = var.get_reg1()
                    Reg2 = var.get_reg2()
                    reg2_var_list.append(VarInfo(var_name, var_size, [Reg1, Reg2], var_type))

            # This variable is scattered
            elif var.is_scattered:
                pass

    # return: list: [[name, size, type,addr],[name, size, type,addr],....]
    return [stk_var_list,reg1_var_list,reg2_var_list]



def GetFunctionStackTrace():
    ''' 
    Get all function base addresses on the function call chain
    Return: function call chain sequence, function base address structure dictionary,
    '''
    CpuInfo.create_instance()
    _,stack_pointer_name,_,instruction_pointer_name = GetStackRegsName()
    try:
        sp_reg_value = get_reg_val(stack_pointer_name)
        ip_reg_value = get_reg_val(instruction_pointer_name)
    except Exception:
        return [],{},[]


    func_frame_trace = {}
    func_frame_less_trace = []
    func_trace_order = []

    tid = get_current_thread()
    trace = call_stack_t()
    if collect_stack_trace(tid, trace):
        frame_depth = trace.size()
        stackframe_address = sp_reg_value
        instruction_address = ip_reg_value

        for depth in range(frame_depth - 1):

            func = get_fchunk(instruction_address)
            func_base_addr = GetFrameBaseAddress(func,instruction_address,stackframe_address,CpuInfo.instance.bitness,CpuInfo.instance.endinness, depth)

            # Find the base address of the upper layer function based on the information

            if func_base_addr is not None:
                instruction_address = trace[depth+1].callea
                stackframe_address = func_base_addr + CpuInfo.instance.bitnessSize
                func_frame_trace[func_base_addr] = func
                func_trace_order.append(0)
            else:
                func_frame_less_trace.append(func)
                func_trace_order.append(1)

    return func_trace_order,func_frame_trace,func_frame_less_trace
