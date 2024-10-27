import idaapi
import idc
import ida_funcs
import ida_frame
import ida_struct
import ida_dbg
import ida_idd

# 函数信息

# 栈基址 + 偏移地址 -> 变量位置

# 栈帧大小




# 获取返回地址作为基址
# func = ida_funcs.get_fchunk(ip_reg_value)
# frame = ida_frame.get_frame(ip_reg_value)

# 获取返回地址作为基址
def GetFrameBaseAddress(func,ip_reg_value, sp_reg_value,bitness,endinness):

    pointer_size = bitness // 8


    if(func == None):
        return None
    func_flags = func.flags

    func_base_addr = sp_reg_value
    frame = func.frame

    # 分析开始条件：栈帧分析完毕    栈帧使用了栈基址寄存器   不存在特殊的栈帧用法   
    if not (func_flags & ida_funcs.FUNC_FRAME) or  ( func_flags & ida_funcs.FUNC_FUZZY_SP):
        return None


    # 基址寻找方式：使用栈跟踪得到的返回地址从栈顶向下寻找 

    # 通过func.points寻找基址
    for i in range(func.points.count):
        stkpnt = func.points[i]
        if(stkpnt.ea > ip_reg_value):
            break

        func_base_addr = sp_reg_value - stkpnt.spd 

    # 通过堆栈调用寻找基址
    tid = ida_dbg.get_current_thread()
    trace = ida_idd.call_stack_t()
    return_ea = None
    if (ida_dbg.collect_stack_trace(tid, trace) and len(trace) > 1):
        frame = trace[1]
        return_ea = frame.callea

    # 检查基址的下一地址是否为返回地址
    if(return_ea != None):
        addr_bytes = idc.get_bytes(func_base_addr,pointer_size)

        print(hex(return_ea))
        print(hex(int.from_bytes(addr_bytes, byteorder = endinness)))

        if(return_ea == int.from_bytes(addr_bytes, byteorder = endinness)):
            return func_base_addr
    return None



def GetstkvarAddress(func,func_base_addr):
    stkvar_dict = {}

    frame = func.frame    
    struct_ptr = ida_struct.get_struc(frame)

    # 基地址
    lvar_base_addr = ida_frame.frame_off_retaddr(func)

    if struct_ptr is not None:
        if(struct_ptr.is_frame()):
            for mptr in struct_ptr.members:

                name = ida_struct.get_member_name(mptr.id)
                size = mptr.get_size()

                offset = mptr.soff
                # typeinfo = ida_struct.get_member_tinfo(mptr.id)

                addr = func_base_addr - lvar_base_addr + offset
                stkvar_dict[addr] = [name,size]
    return stkvar_dict


