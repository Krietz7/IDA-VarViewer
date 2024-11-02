import idaapi
import idc

from StackView.Config import *

from PyQt5 import QtWidgets

import time
import string
import uuid


from StackView.DbgStackInspector import *
from StackView.QtContainers.VariableContainer import *
from StackView.Dbg_Hooks import *
from StackView.FunctionInfo import *
from StackView.TypeConversion import *


class VariableViewer(idaapi.PluginForm):
    def __init__(self):
        super(VariableViewer, self).__init__()    # 初始化父类
        self.Bitness = CPUinfo.bitness  # 位数
        self.bitnessSize = self.Bitness // 8
        self.endinness = CPUinfo.endinness
        self.base_pointer_name,self.stack_pointer_name,self.two_pointer_name,self.instruction_pointer_name = GetStackRegsName()


        self.frameusingfunctiondict = {}
        self.framelessfunctionlist = []
        self.func_stkvar_dict = {}
        self.func_regvar_dict = {}



    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)  
        self.InitGUI()

    def InitGUI(self):
        self.hbox = QtWidgets.QVBoxLayout()

        self.VariableContainer = VariableContainer(self.parent)

        self.hbox.setContentsMargins(0, 0, 0, 0)
        self.hbox.addWidget(self.VariableContainer)
        # 设置父窗口的布局
        self.parent.setLayout(self.hbox)
        
        if(GetDbgStatus()):
            self.VariableContainer.backgroundcolor = DEBUG_BACKGROUND_COLOR
            self.VariableContainer.reset_QSS()

        self.InitDbgHooks()
        
        if(GetDbgStatus()):
            self.InitVariableContainer()
            self.RefreshVariableContainer()

    def InitDbgHooks(self):
        def callbacks(operation):
            # 调试暂停
            if(operation == 0):
                # 窗口在前台显示
                
                self.RefreshVariableContainer()
                self.VariableContainer.RefreshWindow()




        self.hook = DebugHooks(callbacks)
        self.hook.hook()


    def InitVariableContainer(self):
        # Watching 
        # Current focus in
        # Local variables
        # Global variables

        self.VariableContainer.add_top_level_item("watching","Watching",TOP_ITEM_COLOR)
        self.VariableContainer.add_top_level_item("focusin","Current forus in",TOP_ITEM_COLOR)
        self.VariableContainer.add_top_level_item("lvar","Local variables",TOP_ITEM_COLOR)
        self.VariableContainer.add_top_level_item("gvar","Global variables",TOP_ITEM_COLOR)
        self.VariableContainer.RefreshWindow()




    # 更新整个变量窗口
    def RefreshVariableContainer(self):
        self.RefreshLocalvariables()




        self.VariableContainer.RefreshWindow()


    # 更新本地变量部分窗口
    def RefreshLocalvariables(self):
        self.AddLocalvaribles()
        self.RefreshLocalvariblesValue()











    # 获取所有的本地变量并添加到窗口
    def AddLocalvaribles(self):
        func_trace_order,func_frame_trace,func_frame_less_trace = self.GetFunctionStackTrace()
        self.Removefinishfuction(func_frame_trace,func_frame_less_trace)

        while(len(func_trace_order) != 0):
            order = func_trace_order.pop()
            if(order == 0):
                base_address,func = func_frame_trace.popitem()

                func_name = ida_funcs.get_func_name(func.start_ea)
                func_id = f"{func_name}_{base_address:X}"

                stk_var_list,reg1_var_list,reg2_var_list = GetFuncLocationVarAt(func)
                if(base_address not in self.frameusingfunctiondict and self.VariableContainer.add_func_items( \
                    "lvar",func_id,f"{func_name}({base_address:X})",FUNCTION_ITEM_COLOR)):

                    self.frameusingfunctiondict[base_address] = ["lvar",func_id]
                    self.AddStkVar(base_address,func_id,func,stk_var_list)
                    self.AddRegVar(func_id,func,reg1_var_list)
        
            elif(order == 1):
                func = func_frame_less_trace.pop()
                if(func == None):
                    continue
                func_name = ida_funcs.get_func_name(func.start_ea)
                func_id = f"{func_name}_{str(uuid.uuid4())}"

                stk_var_list,reg1_var_list,reg2_var_list = GetFuncLocationVarAt(func)
                if not any(sublist[0] == func for sublist in self.framelessfunctionlist):
                    if(self.VariableContainer.add_func_items("lvar",func_id,f"{func_name}",FUNCTION_ITEM_COLOR)):
                        self.framelessfunctionlist.append([func,["lvar",func_id]])
                        self.AddRegVar(func_id,func,reg1_var_list)









        self.VariableContainer.expand_nodes()



    def AddStkVar(self,base_address,func_id,func,stk_var_list):
        lvar_base_addr = ida_frame.frame_off_retaddr(func)

        for stkvar in stk_var_list:
            varname = stkvar[0]
            varsize = stkvar[1]
            vartype = stkvar[2]
            varaddr = stkvar[3] + base_address - lvar_base_addr

            print(varname,stkvar[3],base_address,lvar_base_addr,varaddr)


            if(vartype.get_realtype() not in [ida_typeinf.BT_ARRAY,ida_typeinf.BTF_STRUCT,ida_typeinf.BT_PTR]):
                varaddrstr = "{}".format(ida_name.get_nice_colored_name(varaddr,ida_name.GNCN_NOCOLOR))
                varstructstr = GetSturctName(vartype)
                varid = f"{varname}_{uuid.uuid4()}"
                
                self.VariableContainer.add_variable_line("lvar",func_id,varid,varname,varstructstr,None,varaddrstr,STKVAR_NAME_COLOR)

                memberid = f"test_{uuid.uuid4()}"
                self.VariableContainer.add_varible_member(varid,memberid,"test")

                if(func_id not in self.func_stkvar_dict.keys()):
                    self.func_stkvar_dict[func_id] = [[varid,varname,varsize,vartype,varaddr]]
                else:
                    self.func_stkvar_dict[func_id].append([varid,varname,varsize,vartype,varaddr])
            elif(vartype.get_realtype() == ida_typeinf.BT_ARRAY):
                elems_type, elems_num = GetArrayElemInfo(vartype)
                print(elems_type, elems_num)
                elem_size = elems_type.get_size()
                elem_structstr =  GetSturctName(elems_type)
                for i in range(elems_num):
                    elem_name = f"{varname}[{i}]"
                    elem_id = f"{varname}_{uuid.uuid4()}"
                    elem_addr = varaddr + elem_size * i
                    elem_addr_str = "{}".format(ida_name.get_nice_colored_name(elem_addr,ida_name.GNCN_NOCOLOR))


                    self.VariableContainer.add_variable_line("lvar",func_id,elem_id,elem_name,elem_structstr,None,elem_addr_str,STKVAR_NAME_COLOR)


                    if(func_id not in self.func_stkvar_dict.keys()):
                        self.func_stkvar_dict[func_id] = [[elem_id,elem_name,elem_size,elems_type,elem_addr]]
                    else:
                        self.func_stkvar_dict[func_id].append([elem_id,elem_name,elem_size,elems_type,elem_addr])





    def AddRegVar(self,func_id,func,reg1_var_list):
        for regvar in reg1_var_list:
            varname = regvar[0]
            varsize = regvar[1]
            vartype = regvar[2]
            varatreg = regvar[3]
            
            varatregstr = GetRegName(varatreg,varsize)
            varstructstr = GetSturctName(vartype)
            varid = f"{varname}_{uuid.uuid4()}"

            
            if(vartype.get_realtype() not in [ida_typeinf.BT_ARRAY,ida_typeinf.BTF_STRUCT,ida_typeinf.BT_PTR]):
                self.VariableContainer.add_variable_line("lvar",func_id,varid,varname,varstructstr,None,varatregstr,REGVAR_NAME_COLOR)

                if(func_id not in self.func_regvar_dict.keys()):
                    self.func_regvar_dict[func_id] = [[varid,varname,varsize,vartype,varatreg]]
                else:
                    self.func_regvar_dict[func_id].append([varid,varname,varsize,vartype,varatreg])
            else:
                pass







    # 获取本地变量值并更新窗口
    def RefreshLocalvariblesValue(self):
        for func_vars in self.func_stkvar_dict.values():
            for lvar in func_vars:
                varid = lvar[0]
                varsize = lvar[2]
                vartype = lvar[3]
                varaddr = lvar[4]
                if(vartype.get_realtype() not in [ida_typeinf.BT_ARRAY,ida_typeinf.BTF_STRUCT,ida_typeinf.BT_PTR]):
                    var_byte = idc.get_bytes(varaddr,varsize)
                    var_value = ConversionByteToStr(var_byte,varsize,vartype)

                    self.VariableContainer.EditVaribleInfo(varid,var_value,2)
                elif(vartype.get_realtype() == ida_typeinf.BT_ARRAY):
                    pass







        for func_vars in self.func_regvar_dict.values():
            for lvar in func_vars:
                varid = lvar[0]
                varsize = lvar[2]
                vartype = lvar[3]
                varatreg = lvar[4]

                out = None
                regname = ida_hexrays.get_mreg_name(varatreg,varsize,out)
                if(vartype.get_realtype() not in [ida_typeinf.BT_ARRAY,ida_typeinf.BTF_STRUCT,ida_typeinf.BT_PTR]):
                    var_byte =  ida_dbg.get_reg_val(regname)
                    var_value = ConversionIntToStr(var_byte, varsize, vartype)

                    self.VariableContainer.EditVaribleInfo(varid,var_value,2)
                elif(vartype.get_realtype() == ida_typeinf.BT_ARRAY):
                    pass















    def Removefinishfuction(self,func_frame_trace,func_frame_less_trace):
        # 结束函数后，从列表中删除
        for base_address in list(self.frameusingfunctiondict.keys()):
            if(base_address not in func_frame_trace.keys()):
                t = self.VariableContainer.RemoveFunc(self.frameusingfunctiondict[base_address][0],self.frameusingfunctiondict[base_address][1])
                if(self.frameusingfunctiondict[base_address][1] in self.func_stkvar_dict.keys()):
                    self.func_stkvar_dict.pop(self.frameusingfunctiondict[base_address][1])
                self.frameusingfunctiondict.pop(base_address)


        for func,func_id in self.framelessfunctionlist:
            if(func not in func_frame_less_trace):
                t = self.VariableContainer.RemoveFunc(func_id[0],func_id[1])
                self.framelessfunctionlist.remove([func,func_id])       
        







    # 获取函数调用链上的所有函数基址  返回：函数调用链顺序 函数基址 结构体 字典
    def GetFunctionStackTrace(self):
        try:
            sp_reg_value = idaapi.get_reg_val(self.stack_pointer_name)
            ip_reg_value = idaapi.get_reg_val(self.instruction_pointer_name)
        except:
            return [],{},[]


        func_frame_trace = {}
        func_frame_less_trace = []
        func_trace_order = []

        tid = ida_dbg.get_current_thread()
        trace = ida_idd.call_stack_t()
        if (ida_dbg.collect_stack_trace(tid, trace)):
            frame_depth = trace.size()
            stackframe_address = sp_reg_value
            instruction_address = ip_reg_value

            for depth in range(frame_depth - 1):

                func = ida_funcs.get_fchunk(instruction_address)
                func_base_addr = GetFrameBaseAddress(func,instruction_address,stackframe_address,self.Bitness,self.endinness, depth)

                # 根据信息寻找上一层函数的基址

                if(func_base_addr != None):
                    instruction_address = trace[depth+1].callea
                    stackframe_address = func_base_addr + self.bitnessSize
                    func_frame_trace[func_base_addr] = func
                    func_trace_order.append(0)
                else:
                    func_frame_less_trace.append(func)
                    func_trace_order.append(1)


        return func_trace_order,func_frame_trace,func_frame_less_trace


    def OnClose(self, form):
        if self.hook:
            self.hook.unhook()
