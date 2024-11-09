import string
import uuid

import idaapi
import idc
from ida_frame import frame_off_retaddr
from ida_funcs import get_func_name
from ida_name import get_nice_colored_name,GNCN_NOCOLOR
from ida_dbg import get_reg_val
from ida_hexrays import get_mreg_name
from PyQt5.QtWidgets import QVBoxLayout

from VarViewer.config import *
from VarViewer.dbg_stack import *
from VarViewer.dbg_hook import *
from VarViewer.dbg_func import *
from VarViewer.var_type_handlers import *
from VarViewer.QtContainers.VariableContainer import *


# varible flags
GET_VALUE_FROM_STACK = 0
GET_VALUE_FROM_REGISTER = 1
GET_VALUE_FROM_CONTAINER = 2
GET_VALUE_BY_POINTER = 4

class VariableViewer(idaapi.PluginForm):
    def __init__(self):
        super().__init__()
        CpuInfo.create_instance()
        self.Bitness = CpuInfo.instance.bitness
        self.bitnessSize = self.Bitness // 8
        self.endinness = CpuInfo.instance.endinness
        self.base_pointer_name,self.stack_pointer_name,self.two_pointer_name,self.instruction_pointer_name = GetStackRegsName()


        self.frameusingfunctiondict = {} # Functions that using stack frame
        self.framelessfunctionlist = [] # Functions that do not use the stack frame
        self.func_var_dict = {"gvar":[]} # Record all variable IDs under a function
        self.varid_dict = {} # Record the variable information corresponding to the variable ID and its sub-member variable information

        self.parent = None
        self.hbox = None
        self.VariableContainer = None
        self.hook = None

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.InitGUI()

    def InitGUI(self):
        self.hbox = QVBoxLayout()
        self.VariableContainer = VariableContainer(self.parent,self)

        self.hbox.setContentsMargins(0, 0, 0, 0)
        self.hbox.addWidget(self.VariableContainer)
        self.parent.setLayout(self.hbox)

        if GetDbgStatus():
            self.VariableContainer.backgroundcolor = DEBUG_BACKGROUND_COLOR
            self.VariableContainer.backgroundcolor2 = DEBUG_BACKGROUND_LINE_COLOR2
            self.VariableContainer.reset_QSS()

            self.InitVariableContainer()
            self.RefreshVariableContainer()
        self.InitDbgHooks()



    def InitDbgHooks(self):
        def callbacks(operation):
            if operation == 0:
                if self.VariableContainer.isVisible():
                    self.RefreshVariableContainer()
                    self.VariableContainer.refresh_window()

        self.hook = DebugHooks(callbacks)
        self.hook.hook()


    def InitVariableContainer(self):
        self.frameusingfunctiondict.clear()
        self.framelessfunctionlist.clear()
        self.func_var_dict = {"gvar":[]}
        self.varid_dict.clear()

        self.RefreshVariableContainer()
        self.VariableContainer.refresh_window()


    def RefreshVariableContainer(self):
        self.AddLocalvaribles()
        self.RefreshLocalvariblesValue()
        self.VariableContainer.refresh_window()

    def AddLocalvaribles(self):
        '''Get all local variables and add them to the window'''
        func_trace_order,func_frame_trace,func_frame_less_trace = GetFunctionStackTrace()
        self.remove_finish_fuction(func_frame_trace,func_frame_less_trace)

        while len(func_trace_order) != 0:
            order = func_trace_order.pop()
            if order == 0:
                base_address,func = func_frame_trace.popitem()

                func_name = get_func_name(func.start_ea)
                func_id = f"{func_name}_{base_address:X}"

                stk_var_list,reg1_var_list,reg2_var_list = GetFuncLocationVar(func)
                if(base_address not in self.frameusingfunctiondict and self.VariableContainer.add_func_item( \
                    "lvar",func_id,f"{func_name}({base_address:X})",FUNCTION_ITEM_COLOR)):

                    self.frameusingfunctiondict[base_address] = ["lvar",func_id]
                    self.add_stk_var(base_address,func_id,func,stk_var_list)
                    self.add_reg_var(func_id,func,reg1_var_list)

            elif order == 1:
                func = func_frame_less_trace.pop()
                if func is None:
                    continue
                func_name = get_func_name(func.start_ea)
                func_id = f"{func_name}_{str(uuid.uuid4())}"

                stk_var_list,reg1_var_list,reg2_var_list = GetFuncLocationVar(func)
                if not any(sublist[0] == func for sublist in self.framelessfunctionlist):
                    if self.VariableContainer.add_func_item("lvar",func_id,f"{func_name}",FUNCTION_ITEM_COLOR):
                        self.framelessfunctionlist.append([func,["lvar",func_id]])
                        self.add_reg_var(func_id,func,reg1_var_list)


    def add_stk_var(self,base_address,func_id,func,stk_var_list):
        lvar_base_addr = frame_off_retaddr(func)

        for stkvar in stk_var_list:
            varname = stkvar.name
            varsize = stkvar.size
            vartype = stkvar.type
            varaddr = stkvar.addr + base_address - lvar_base_addr



            varaddrstr = get_nice_colored_name(varaddr,GNCN_NOCOLOR)
            varstructstr = GetTypeName(vartype)
            varid = f"{varname}_{uuid.uuid4()}"

            self.VariableContainer.add_variable_item(func_id,varid,varname,varstructstr,None,varaddrstr,STKVAR_NAME_COLOR)
            var_members = self.AddVariableMembers(varid,varname,vartype)

            self.varid_dict[varid] = [GET_VALUE_FROM_STACK,VarInfo(varname,varsize,varaddr,vartype),var_members]
            if func_id not in self.func_var_dict:
                self.func_var_dict[func_id] = [varid]
            else:
                self.func_var_dict[func_id].append(varid)


    def add_reg_var(self,func_id,func,reg1_var_list):
        for regvar in reg1_var_list:
            varname = regvar.name
            varsize = regvar.size
            vartype = regvar.type
            varatreg = regvar.addr

            varatregstr = GetRegName(varatreg,varsize)
            varstructstr = GetTypeName(vartype)
            varid = f"{varname}_{uuid.uuid4()}"

            self.VariableContainer.add_variable_item(func_id,varid,varname,varstructstr,None,varatregstr,REGVAR_NAME_COLOR)
            var_members = self.AddVariableMembers(varid,varname,vartype)

            self.varid_dict[varid] = [GET_VALUE_FROM_REGISTER,VarInfo(varname,varsize,varatreg,vartype),var_members]
            if func_id not in self.func_var_dict:
                self.func_var_dict[func_id] = [varid]
            else:
                self.func_var_dict[func_id].append(varid)


    def AddVariableMembers(self,varid,varname,vartype):
        if(vartype.get_realtype() not in [ida_typeinf.BT_ARRAY,ida_typeinf.BTF_STRUCT,ida_typeinf.BT_PTR]):
            return []

        result = []
        if vartype.get_realtype() == ida_typeinf.BT_ARRAY:
            elems_type, elems_num = GetArrayElemInfo(vartype)
            elem_size = elems_type.get_size()

            for i in range(elems_num):
                elem_name = f"{varname}[{i}]"
                elem_id = f"{varname}_{uuid.uuid4()}"
                elem_addr = 0 + i * elem_size
                elem_structstr = GetTypeName(elems_type)

                self.VariableContainer.add_varible_member(varid,elem_id,elem_name,elem_structstr)
                elem_members = self.AddVariableMembers(elem_id,elem_name,elems_type)

                self.varid_dict[elem_id] = [GET_VALUE_FROM_CONTAINER,VarInfo(elem_name,elem_size,elem_addr,elems_type),elem_members]
                result.append(elem_id)


        elif vartype.get_realtype() == ida_typeinf.BTF_STRUCT:
            struct_members = GetStructMembersInfo(vartype)

            for member_info in struct_members:
                member_name = member_info.name
                member_id = f"{member_name}_{uuid.uuid4()}"

                member_type = member_info.type
                member_soff = member_info.addr
                member_size = member_info.size

                member_structstr = GetTypeName(member_type)
                self.VariableContainer.add_varible_member(varid,member_id,member_name,member_structstr)
                member_members = self.AddVariableMembers(member_id,member_name,member_type)

                self.varid_dict[member_id] = [GET_VALUE_FROM_CONTAINER,VarInfo(member_name,member_size,member_soff,member_type),member_members]
                result.append(member_id)

        elif vartype.get_realtype() == ida_typeinf.BT_PTR:
            target_type,target_size = GetPtrTargetInfo(vartype)
            target_name = f"*{varname}"
            target_id = f"{target_name}_{uuid.uuid4()}"
            target_structstr = GetTypeName(target_type)

            self.VariableContainer.add_varible_member(varid,target_id,target_name,target_structstr)
            target_members = self.AddVariableMembers(target_id,target_name,target_type)

            self.varid_dict[target_id] = [GET_VALUE_BY_POINTER,VarInfo(target_name,target_size,0,target_type),target_members]
            result.append(target_id)

        return result

    def RefreshLocalvariblesValue(self):
        for func_vars in self.func_var_dict.values():
            for varid in func_vars:
                self.RefreshVarible(varid)
        func_id = next(reversed(self.func_var_dict))
        self.VariableContainer.expand_node("lvar")
        self.VariableContainer.expand_node(func_id)


    def RefreshVarible(self,varid,containerbytes = None,containeraddr = None):
        varflag = self.varid_dict[varid][0]
        varinfo = self.varid_dict[varid][1]
        varsize = varinfo.size
        vartype = varinfo.type
        var_pre_value = varinfo.value
        var_bytes = None
        varaddr = None

        if varflag == GET_VALUE_FROM_STACK:
            varaddr = varinfo.addr
            var_bytes = idc.get_bytes(varaddr,varsize)
            var_value = ConversionBytesToStr(var_bytes,varsize,vartype)

            if var_pre_value != var_value:
                self.VariableContainer.EditVaribleInfo(varid,var_value,2)
                self.varid_dict[varid][1].value = var_value


        elif varflag == GET_VALUE_FROM_REGISTER:
            varatreg = varinfo.addr

            out = None
            regname = get_mreg_name(varatreg,varsize,out)
            var_bytes =  get_reg_val(regname).to_bytes(CpuInfo.instance.bitnessSize,CpuInfo.instance.endinness)
            var_value = ConversionBytesToStr(var_bytes, varsize, vartype)

            if var_pre_value != var_value:
                self.VariableContainer.EditVaribleInfo(varid,var_value,2)
                self.varid_dict[varid][1].value = var_value

        elif varflag == GET_VALUE_FROM_CONTAINER:
            if(containerbytes is None or containerbytes == ""):
                self.VariableContainer.EditVaribleInfo(varid,"",2)
                self.VariableContainer.EditVaribleInfo(varid,"",3)
            else:
                varaddr = varinfo.addr
                var_bytes = containerbytes[varaddr:varaddr+varsize]
                var_value = ConversionBytesToStr(var_bytes,varsize,vartype)

                if var_pre_value != var_value:
                    self.VariableContainer.EditVaribleInfo(varid,var_value,2)
                    if containeraddr is not None:
                        self.VariableContainer.EditVaribleInfo(varid,f"{(containeraddr + varaddr):X}",3)

        elif varflag == GET_VALUE_BY_POINTER:
            if(containerbytes is not None or containerbytes == ""):
                offset = varinfo.addr
                varaddr = int.from_bytes(containerbytes[:CpuInfo.instance.bitnessSize],CpuInfo.instance.endinness) + offset

            if(varaddr is not None and idaapi.is_loaded(varaddr) and idaapi.is_loaded(varaddr + varsize) and varsize > 0):

                var_bytes = idc.get_bytes(varaddr,varsize)
                var_value = ConversionBytesToStr(var_bytes,varsize,vartype)
                if var_pre_value != var_value:
                    self.VariableContainer.EditVaribleInfo(varid,var_value,2)
                    self.VariableContainer.EditVaribleInfo(varid,f"{varaddr:X}",3)
            else:
                self.VariableContainer.EditVaribleInfo(varid,"",2)
                self.VariableContainer.EditVaribleInfo(varid,"",3)

        if(self.varid_dict[varid][2] != [] and var_bytes != b""):
            varaddr = varaddr if containeraddr is None else containeraddr + varaddr
            for member_id in self.varid_dict[varid][2]:
                self.RefreshVarible(member_id,var_bytes,varaddr)


    def remove_variable(self, varid):
        if varid in self.varid_dict:
            members_id = self.varid_dict[varid][2]
            for child_varid in members_id:
                self.remove_variable(child_varid)

            del self.varid_dict[varid]



    def remove_finish_fuction(self,func_frame_trace,func_frame_less_trace):
        # After the function ends, delete it from the list
        for base_address in list(self.frameusingfunctiondict.keys()):
            if base_address not in func_frame_trace:

                # Remove function items from the Qtree interface
                self.VariableContainer.RemoveItem(self.frameusingfunctiondict[base_address][0],self.frameusingfunctiondict[base_address][1])
                if self.frameusingfunctiondict[base_address][1] in self.func_var_dict:

                    # Remove variable information
                    for varid in self.func_var_dict[self.frameusingfunctiondict[base_address][1]]:
                        self.remove_variable(varid)

                    # Remove function information
                    self.func_var_dict.pop(self.frameusingfunctiondict[base_address][1])
                self.frameusingfunctiondict.pop(base_address)


        for func,func_id in self.framelessfunctionlist:
            if func not in func_frame_less_trace:
                self.VariableContainer.RemoveItem(func_id[0],func_id[1])
                self.framelessfunctionlist.remove([func,func_id])



    def widget_double_click(self,selected_data):
        if(selected_data in [None,""]):
            return

        if all(c in "0123456789abcdefABCDEF" for c in selected_data):
            selected_data = int(selected_data,16)
            if(selected_data and idc.is_loaded(selected_data)):
                idaapi.jumpto(selected_data)

        elif(c in string.printable for c in selected_data):
            target_addr = idc.get_name_ea(idc.BADADDR,selected_data)
            if target_addr != idc.BADADDR:
                idaapi.jumpto(target_addr)


    def reset_pointer_size(self,VarID):
        if VarID not in self.varid_dict:
            return False

        elif self.varid_dict[VarID][1].type.get_realtype() != ida_typeinf.BT_PTR:
            return False
        pointerInfo = self.varid_dict[VarID][1]

        elems_type, _ = GetPtrTargetInfo(pointerInfo.type)
        elem_size = elems_type.get_size()
        arrlen = pointerInfo.size // elem_size

        form = Arrlen_input_form(arrlen)
        IsChange = form.Execute()
        if IsChange:
            arrlen = form.inputlen

            self.varid_dict[VarID][1].size = arrlen * elem_size

            self.VariableContainer.del_varible_members(VarID)
            self.varid_dict[VarID][2].clear()
            for members_id in self.varid_dict[VarID][2]:
                self.remove_variable(members_id)

            for i in range(arrlen):
                elem_name = f"{pointerInfo.name}[{i}]"
                elem_id = f"{pointerInfo.name}_{uuid.uuid4()}"
                elem_addr = 0 + i * elem_size
                elem_structstr = GetTypeName(elems_type)

                self.VariableContainer.add_varible_member(VarID,elem_id,elem_name,elem_structstr)
                elem_members = self.AddVariableMembers(elem_id,elem_name,elems_type)

                self.varid_dict[elem_id] = [GET_VALUE_BY_POINTER,VarInfo(elem_name,elem_size,elem_addr,elems_type),elem_members]
                self.varid_dict[VarID][2].append(elem_id)

            self.RefreshLocalvariblesValue()


    def add_global_var(self):
        form = GlobalVar_input_form()
        IsChange = form.Execute()
        if IsChange:
            gvar_name = form.gvar_name
            gvar_addr = idaapi.get_name_ea(idaapi.BADADDR,gvar_name)
            if idaapi.is_loaded(gvar_addr):
                gvar_id = f"{gvar_name}_{uuid.uuid4()}"
                gvar_size = idc.get_item_size(gvar_addr)
                gvar_addr_str = f"{get_nice_colored_name(gvar_addr,GNCN_NOCOLOR)}"

                self.VariableContainer.add_variable_item("gvar",gvar_id,gvar_name,"bytes",None,gvar_addr_str,REGVAR_NAME_COLOR)

                self.func_var_dict["gvar"].append(gvar_id)
                self.varid_dict[gvar_id] = [GET_VALUE_FROM_STACK,\
                                            VarInfo(gvar_name,gvar_size,gvar_addr,\
                                                    ida_typeinf.tinfo_t(ida_typeinf.BT_UNKNOWN)),[]]

                self.RefreshVarible(gvar_id)

    def OnClose(self, form):
        if self.hook:
            self.hook.unhook()

class Arrlen_input_form(idaapi.Form):
    def __init__(self,inputlen):
        self.inputlen = inputlen
        super().__init__(
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
        if fid == self._arrlen.id:
            self.inputlen = self.GetControlValue(self._arrlen)

        return 1

class GlobalVar_input_form(idaapi.Form):
    def __init__(self):
        self.gvar_name = None
        super().__init__(
        r'''
        {FormChangeCb}
        <Add Global var name: {_gvarname}>
        ''',
        {
        "FormChangeCb": self.FormChangeCb(self.OnFormChange),

        "_gvarname": self.StringInput(value = "", swidth = 30),
        }
        )
        self.Compile()

    def OnFormChange(self,fid):
        if fid == self._gvarname.id:
            self.gvar_name = self.GetControlValue(self._gvarname)

        return 1
