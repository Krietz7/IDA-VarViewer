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


# varible flags
GET_VALUE_FROM_STACK = 0
GET_VALUE_FROM_REGISTER = 1
GET_VALUE_FROM_CONTAINER = 2
GET_VALUE_BY_POINTER = 4

class VariableViewer(idaapi.PluginForm):
    def __init__(self):
        super(VariableViewer, self).__init__()    # 初始化父类
        self.Bitness = CPUinfo.bitness  # 位数
        self.bitnessSize = self.Bitness // 8
        self.endinness = CPUinfo.endinness
        self.base_pointer_name,self.stack_pointer_name,self.two_pointer_name,self.instruction_pointer_name = GetStackRegsName()


        self.frameusingfunctiondict = {}
        self.framelessfunctionlist = []
        self.func_var_dict = {}   # 记录一个函数下的所有变量ID
        self.varid_dict = {} # 记录变量ID对应的ID信息及其子成员变量信息




    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)  
        self.InitGUI()

    def InitGUI(self):
        self.hbox = QtWidgets.QVBoxLayout()

        self.VariableContainer = VariableContainer(self.parent,self)

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
                self.RefreshVariableContainer()
                self.VariableContainer.RefreshWindow()




        self.hook = DebugHooks(callbacks)
        self.hook.hook()


    def InitVariableContainer(self):
        # Watching 
        # Current focus in
        # Local variables
        # Global variables


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














    def AddStkVar(self,base_address,func_id,func,stk_var_list):
        lvar_base_addr = ida_frame.frame_off_retaddr(func)

        for stkvar in stk_var_list:
            varname = stkvar[0]
            varsize = stkvar[1]
            vartype = stkvar[2]
            varaddr = stkvar[3] + base_address - lvar_base_addr



            varaddrstr = "{}".format(ida_name.get_nice_colored_name(varaddr,ida_name.GNCN_NOCOLOR))
            varstructstr = GetSturctName(vartype)
            varid = f"{varname}_{uuid.uuid4()}"
            
            self.VariableContainer.add_variable_line("lvar",func_id,varid,varname,varstructstr,None,varaddrstr,STKVAR_NAME_COLOR)
            var_members = self.AddVariableMembers(varid,varname,vartype)

            self.varid_dict[varid] = [GET_VALUE_FROM_STACK,varname,varsize,vartype,varaddr,var_members]
            if(func_id not in self.func_var_dict.keys()):
                self.func_var_dict[func_id] = [varid]
            else:
                self.func_var_dict[func_id].append(varid)
  





    def AddRegVar(self,func_id,func,reg1_var_list):
        for regvar in reg1_var_list:
            varname = regvar[0]
            varsize = regvar[1]
            vartype = regvar[2]
            varatreg = regvar[3]
            
            varatregstr = GetRegName(varatreg,varsize)
            varstructstr = GetSturctName(vartype)
            varid = f"{varname}_{uuid.uuid4()}"

            
            self.VariableContainer.add_variable_line("lvar",func_id,varid,varname,varstructstr,None,varatregstr,REGVAR_NAME_COLOR)
            var_members = self.AddVariableMembers(varid,varname,vartype)

            self.varid_dict[varid] = [GET_VALUE_FROM_REGISTER,varname,varsize,vartype,varatreg,var_members]
            if(func_id not in self.func_var_dict.keys()):
                self.func_var_dict[func_id] = [varid]
            else:
                self.func_var_dict[func_id].append(varid)







    def AddVariableMembers(self,varid,varname,vartype):
        if(vartype.get_realtype() not in [ida_typeinf.BT_ARRAY,ida_typeinf.BTF_STRUCT,ida_typeinf.BT_PTR]):
            return []

        result = []
        if(vartype.get_realtype() == ida_typeinf.BT_ARRAY):
            elems_type, elems_num = GetArrayElemInfo(vartype)
            elem_size = elems_type.get_size()
            
            for i in range(elems_num):
                elem_name = f"{varname}[{i}]"
                elem_id = f"{varname}_{uuid.uuid4()}"
                elem_addr = 0 + i * elem_size
                elem_structstr = GetSturctName(elems_type)

                self.VariableContainer.add_varible_member(varid,elem_id,elem_name,elem_structstr)
                elem_members = self.AddVariableMembers(elem_id,elem_name,elems_type)

                self.varid_dict[elem_id] = [GET_VALUE_FROM_CONTAINER,elem_name,elem_size,elems_type,elem_addr,elem_members]
                result.append(elem_id)
                    





        elif(vartype.get_realtype() == ida_typeinf.BTF_STRUCT):
            struct_members = GetStructMemberInfo(vartype)

            for member_info in struct_members:
                member_name = member_info[0]
                member_id = f"{member_name}_{uuid.uuid4()}"

                member_type = member_info[1]
                member_soff = member_info[2]
                member_size = member_info[3]

                member_structstr = GetSturctName(member_type)
                self.VariableContainer.add_varible_member(varid,member_id,member_name,member_structstr)
                member_members = self.AddVariableMembers(member_id,member_name,member_type)

                self.varid_dict[member_id] = [GET_VALUE_FROM_CONTAINER,member_name,member_size,member_type,member_soff,member_members]
                result.append(member_id)








        elif(vartype.get_realtype() == ida_typeinf.BT_PTR):
            target_type,target_size = GetPtrTargetInfo(vartype)
            target_name = f"*{varname}"
            target_id = f"{target_name}_{uuid.uuid4()}"
            target_structstr = GetSturctName(target_type)

            self.VariableContainer.add_varible_member(varid,target_id,target_name,target_structstr)
            target_members = self.AddVariableMembers(target_id,target_name,target_type)

            self.varid_dict[target_id] = [GET_VALUE_BY_POINTER,target_name,target_size,target_type,0,target_members]
            result.append(target_id)

        return result







    # 获取本地变量值并更新窗口
    def RefreshLocalvariblesValue(self):
        for func_vars in self.func_var_dict.values():
            for varid in func_vars:
                self.RefreshVarible(varid)




    # 传入变量信息数组： [0:var值获取方式 1:var名称 2:var大小 3:var类型 4:var获取的位置 5:var下的成员]
    def RefreshVarible(self,varid,containerbytes = None,containeraddr = None):
        varinfo = self.varid_dict[varid]
        varflag = varinfo[0]
        varsize = varinfo[2]
        vartype = varinfo[3]
        var_byte = None
        varaddr = None

        if(varflag == GET_VALUE_FROM_STACK):
            varaddr = varinfo[4]
            var_byte = idc.get_bytes(varaddr,varsize)
            var_value = ConversionByteToStr(var_byte,varsize,vartype)

            self.VariableContainer.EditVaribleInfo(varid,var_value,2)



        elif(varflag == GET_VALUE_FROM_REGISTER):
            varatreg = varinfo[4]

            out = None
            regname = ida_hexrays.get_mreg_name(varatreg,varsize,out)

            var_byte =  ida_dbg.get_reg_val(regname).to_bytes(varsize,CPUinfo.endinness)
            var_value = ConversionByteToStr(var_byte, varsize, vartype)

            self.VariableContainer.EditVaribleInfo(varid,var_value,2)

        elif(varflag == GET_VALUE_FROM_CONTAINER):
            if(containerbytes == None or containerbytes == ""):
                self.VariableContainer.EditVaribleInfo(varid,"",2)
                self.VariableContainer.EditVaribleInfo(varid,"",3)
            else:
                varaddr = varinfo[4]
                var_byte = containerbytes[varaddr:varaddr+varsize]
                var_value = ConversionByteToStr(var_byte,varsize,vartype)

                self.VariableContainer.EditVaribleInfo(varid,var_value,2)

                if(containeraddr != None):
                    self.VariableContainer.EditVaribleInfo(varid,hex(containeraddr + varaddr)[2:],3)

        elif(varflag == GET_VALUE_BY_POINTER):
            if(containerbytes != None or containerbytes == ""):
                offset = varinfo[4]
                varaddr = int.from_bytes(containerbytes[:CPUinfo.bitnessSize],CPUinfo.endinness) + offset


            if(varaddr != None and idaapi.is_loaded(varaddr) and idaapi.is_loaded(varaddr + varsize) and varsize > 0):
                
                var_byte = idc.get_bytes(varaddr,varsize)
                var_value = ConversionByteToStr(var_byte,varsize,vartype)
                self.VariableContainer.EditVaribleInfo(varid,var_value,2)
                self.VariableContainer.EditVaribleInfo(varid,hex(varaddr)[2:],3)
            else:
                self.VariableContainer.EditVaribleInfo(varid,"",2)
                self.VariableContainer.EditVaribleInfo(varid,"",3)





        if(varinfo[5] != [] and var_byte != b""):
            for member_id in varinfo[5]:
                self.RefreshVarible(member_id,var_byte,varaddr)






    def remove_variable(self, varid):
        if varid in self.varid_dict:
            var_info = self.varid_dict[varid]

            # 递归删除子成员
            for child_varid in var_info[5]:
                self.remove_variable(child_varid)

            # 从变量字典中移除
            del self.varid_dict[varid]



    def Removefinishfuction(self,func_frame_trace,func_frame_less_trace):
        # 结束函数后，从列表中删除
        for base_address in list(self.frameusingfunctiondict.keys()):
            if(base_address not in func_frame_trace.keys()):

                # 在Qtree界面移除函数
                self.VariableContainer.RemoveFunc(self.frameusingfunctiondict[base_address][0],self.frameusingfunctiondict[base_address][1])
                if(self.frameusingfunctiondict[base_address][1] in self.func_var_dict.keys()):

                    # 移除变量信息
                    for varid in self.func_var_dict[self.frameusingfunctiondict[base_address][1]]:
                        self.remove_variable(varid)

                    # 移除函数信息
                    self.func_var_dict.pop(self.frameusingfunctiondict[base_address][1])
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



    def WidgeDoubleClick(self,selected_data):
        if(selected_data in [None,""]):
            return
        
        if(all(c in "0123456789abcdefABCDEF" for c in selected_data)):
            selected_data = int(selected_data,16)
            if(selected_data and idc.is_loaded(selected_data)):
                idaapi.jumpto(selected_data)

        elif(c in string.printable for c in selected_data):
            target_addr = idc.get_name_ea(idc.BADADDR,selected_data)
            if(target_addr != idc.BADADDR):
                idaapi.jumpto(target_addr)



    def ResetPointerSize(self,VarID):
        if(VarID not in self.varid_dict):
            return False
        

        elif(self.varid_dict[VarID][3].get_realtype() != ida_typeinf.BT_PTR): 
            return False
        pointerInfo = self.varid_dict[VarID]

        elems_type, _ = GetPtrTargetInfo(pointerInfo[3])
        elem_size = elems_type.get_size()
        arrlen = pointerInfo[2] // elem_size



        form = Arrlen_input_form(arrlen)
        IsChange = form.Execute()
        if(IsChange):
            arrlen = form.inputlen

            self.varid_dict[VarID][2] = arrlen * elem_size

            self.VariableContainer.del_varible_members(VarID)
            self.varid_dict[VarID][5].clear()
            for members_id in pointerInfo[5]:
                self.remove_variable(members_id)



            for i in range(arrlen):
                elem_name = f"{pointerInfo[1]}[{i}]"
                elem_id = f"{pointerInfo[1]}_{uuid.uuid4()}"
                elem_addr = 0 + i * elem_size
                elem_structstr = GetSturctName(elems_type)

                self.VariableContainer.add_varible_member(VarID,elem_id,elem_name,elem_structstr)
                elem_members = self.AddVariableMembers(elem_id,elem_name,elems_type)

                self.varid_dict[elem_id] = [GET_VALUE_BY_POINTER,elem_name,elem_size,elems_type,elem_addr,elem_members]
                self.varid_dict[VarID][5].append(elem_id)
            
            self.RefreshLocalvariblesValue()





class Arrlen_input_form(idaapi.Form):
    def __init__(self,inputlen):
        self.inputlen = inputlen;
        super(Arrlen_input_form, self).__init__(
        r'''
        {FormChangeCb}
        <Size of array pointed: {_arrlen}>
        ''',
        {
        "FormChangeCb": self.FormChangeCb(self.OnFormChange),

        "_arrlen": self.NumericInput(value = self.inputlen, swidth = 30),
        }
        )
        self.Compile()
    
    def OnFormChange(self,fid):
        if(fid == self._arrlen.id):
            self.inputlen = self.GetControlValue(self._arrlen)

        return 1
    
