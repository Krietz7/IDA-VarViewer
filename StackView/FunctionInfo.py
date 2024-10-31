import idaapi
import idc
import ida_funcs
import ida_frame
import ida_struct
import ida_dbg
import ida_idd
import ida_funcs
import ida_typeinf
import ida_hexrays

TypeDict = {
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


# 函数信息

# 栈基址 + 偏移地址 -> 变量位置

# 栈帧大小





# 获取执行call指令后的栈顶地址作为基址
def GetFrameBaseAddress(func,ip_reg_value, sp_reg_value,bitness,endinness,trace_depth = 0):

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
    if (ida_dbg.collect_stack_trace(tid, trace) and len(trace) > trace_depth):
        frame = trace[trace_depth + 1]
        return_ea = frame.callea
        return_ea_next_addr = idc.find_code(return_ea,1)

    # 检查基址的下一地址是否为返回地址
    if(return_ea != None):
        addr_bytes = idc.get_bytes(func_base_addr,pointer_size)
        addr_int =  int.from_bytes(addr_bytes, byteorder = endinness)
        if(return_ea == addr_int or return_ea_next_addr == addr_int):
            return func_base_addr
    return None


# 通过基址获取所有栈变量
def GetstkvarAddress(func,func_base_addr,bitnessSize):
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

                addr = (func_base_addr - lvar_base_addr + offset) - (func_base_addr - lvar_base_addr + offset) % bitnessSize
                if(addr not in stkvar_dict):
                    stkvar_dict[addr] = [name,size,addr]
                else:
                    stkvar_dict[addr] += [name,size,func_base_addr - lvar_base_addr + offset]
    return stkvar_dict




    
# 根据函数对象获取其lvar变量 及所在位置
def GetFuncLocationVarAt(f):
    cfunc = ida_hexrays.decompile(f)
    lvars = cfunc.lvars

    stk_var_list = []
    reg1_var_list = []
    reg2_var_list = []

    for var in lvars:
        if(var.used):
            var_name = var.name
            var_size = var.width
            var_type = var.tif

            # 该变量属于栈变量
            if(var.is_stk_var and var.get_stkoff() > 0 ):
                off = var.get_stkoff()
                stk_var_list.append([var_name, var_size, var_type,off])

            # 该变量属于寄存器变量
            elif(var.is_reg_var):
                # 由单个寄存器保存
                if(var.is_reg1 and var.get_reg2() == 0):
                    Reg1 = var.get_reg1() # mreg_t
                    reg1_var_list.append([var_name, var_size, var_type,Reg1])


                # 由两个寄存器保存
                elif(var.is_reg2 and var.get_reg2() != 0):
                    Reg1 = var.get_reg1()
                    Reg2 = var.get_reg2()
                    reg2_var_list.append([var_name, var_size, var_type, [Reg1, Reg2]])
                    pass

            # 变量是否分散
            elif(var.is_scattered):
                var.get_scattered
                pass


    return [stk_var_list,reg1_var_list,reg2_var_list]








