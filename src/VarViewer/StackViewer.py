import string

import idaapi
from ida_funcs import get_func_name
from PyQt5.QtWidgets import QVBoxLayout

from VarViewer.dbg_stack import *
from VarViewer.dbg_hook import *
from VarViewer.dbg_func import *
from VarViewer.var_type_handlers import *
from VarViewer.QtContainers.StackContainer import StackContainer

class StackViewer(idaapi.PluginForm):
    def __init__(self):
        super().__init__()
        CpuInfo.create_instance()
        self.Bitness = CpuInfo.instance.bitness
        self.bitnessSize = CpuInfo.instance.bitnessSize
        self.endinness = CpuInfo.instance.endinness
        self.base_pointer_name,self.stack_pointer_name,\
            self.two_pointer_name,self.instruction_pointer_name = GetStackRegsName()

        self.InitSuccess = False

        self.parent = None
        self.hbox = None
        self.StackContainer = None
        self.hook = None

        # Record the current displayed stack values to determine whether it needs to be updated when refreshing
        # address : [value, next value(if previous value is a address), ...]
        self.StackValues = {}

        # Recode all stack variables
        # address : <StackVarRemark>
        self.StackvarDict = {}

        self.followInReg = self.stack_pointer_name # if None, viewer will follow address
        self.followInAddress = 0


    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.InitGUI()

    def InitGUI(self):
        self.hbox = QVBoxLayout()
        self.StackContainer = StackContainer(self.parent,self.Bitness,self)
        self.hbox.setContentsMargins(0, 0, 0, 0)
        self.hbox.addWidget(self.StackContainer)

        self.parent.setLayout(self.hbox)
        if GetDbgStatus():
            self.StackContainer.backgroundColor = DEBUG_BACKGROUND_COLOR
            self.StackContainer.reset_QSS()
            self.StackContainer.refresh_window()

            self.InitDbgHooks()
            self.InitStackContainer()
            self.StackContainer.refresh_window()

    def InitDbgHooks(self):
        def callbacks(operation):
            if operation == 0:
                if not self.InitSuccess:
                    self.StackContainer.backgroundColor = DEBUG_BACKGROUND_COLOR
                    self.StackContainer.reset_QSS()
                    self.StackContainer.refresh_window()

                    self.InitDbgHooks()
                    self.InitStackContainer()
                    self.StackContainer.refresh_window()

                elif(self.StackContainer.isVisible() and self.InitSuccess):
                    self.RefreshStackContainer()
                    self.StackContainer.refresh_window()
        self.hook = DebugHooks(callbacks)
        self.hook.hook()


    def idc_get_value(self, address):
        if self.Bitness == 64:
            return idc.get_qword(address)
        elif self.Bitness == 32:
            return idc.get_wide_dword(address)
        return None

    def init_stack_line(self,address,add_at_end):
        if add_at_end:
            self.StackContainer.add_line_at_end(address,self.idc_get_value(address))
        else:
            self.StackContainer.add_line_at_begin(address,self.idc_get_value(address))

        self.StackContainer.change_edit_color(address,1,STACK_ADDRESS_COLOR)
        self.set_stack_description(address,self.idc_get_value(address))

    def mark_stack_pointer(self,base_pointer_value,stack_pointer_value):
        if base_pointer_value != stack_pointer_value:
            self.StackContainer.edit_item(base_pointer_value,0,self.base_pointer_name + "->")
            self.StackContainer.change_edit_color(base_pointer_value,0,STACK_POINTS_REGS_COLOR)

            self.StackContainer.edit_item(stack_pointer_value,0,self.stack_pointer_name + "->")
            self.StackContainer.change_edit_color(stack_pointer_value,0,STACK_POINTS_REGS_COLOR)
        else:
            self.StackContainer.edit_item(stack_pointer_value,0,self.two_pointer_name + ">")
            self.StackContainer.change_edit_color(stack_pointer_value,0,STACK_POINTS_REGS_COLOR)

    def add_new_data_above(self, stack_pointer_value, start_address):
        if stack_pointer_value - start_address < STACK_SIZE_ABOVE_MAX * self.bitnessSize:
            load_count = 0
            for current_address in range(start_address - self.bitnessSize,
                                        stack_pointer_value - (STACK_SIZE_ABOVE_MAX + 1) * self.bitnessSize,\
                                        - self.bitnessSize):
                load_count += 1
                if load_count > ONCE_LOAD_SIZE:
                    break
                self.init_stack_line(current_address,False)

    def add_new_data_below(self, stack_pointer_value, end_address):
        if end_address - stack_pointer_value < STACK_SIZE_BELOW_MIN * self.bitnessSize:
            load_count = 0
            for current_address in range(end_address + self.bitnessSize,\
                                        stack_pointer_value + (STACK_SIZE_BELOW_MIN + 1) * self.bitnessSize,\
                                        self.bitnessSize):
                load_count += 1
                if load_count > ONCE_LOAD_SIZE:
                    break
                self.init_stack_line(current_address, True)




    def InitStackContainer(self):
        self.StackValues.clear()
        self.StackvarDict.clear()
        self.followInReg = self.stack_pointer_name

        if GetDbgStatus():
            self.StackContainer.disable_updates()
            self.StackContainer.clear_all_lines()

            try:
                base_pointer_value, stack_pointer_value = GetStackValue()
            except Exception:
                self.StackContainer.enable_updates()
                return False
            if base_pointer_value is None or stack_pointer_value is None:
                return False

            if self.followInReg == self.stack_pointer_name:
                follow_in_address = stack_pointer_value
            elif self.followInReg == self.base_pointer_name:
                follow_in_address = base_pointer_value
            else:
                follow_in_address = self.followInAddress
            if follow_in_address is None:
                return False

            # Initialize based on followIn_address
            self.init_stack_line(follow_in_address,True)

            # Add data above and below follow_in_address
            for i in range(1,STACK_SIZE_ABOVE):
                current_address = follow_in_address - (i * self.bitnessSize)
                self.init_stack_line(current_address,False)
            for i in range(1,STACK_SIZE_BELOW):
                current_address = follow_in_address + (i * self.bitnessSize)
                self.init_stack_line(current_address,True)


            self.RefreshStackContainer()
            self.StackContainer.roll_to_address(follow_in_address)
            self.StackContainer.enable_updates()
            self.StackContainer.refresh_window()

            # initialization completed
            self.InitSuccess = True
            return True

    def RefreshStackContainer(self):
        if GetDbgStatus():
            self.StackContainer.disable_updates()

            try:
                start_address,end_address = self.StackContainer.get_address_range()
                base_pointer_value, stack_pointer_value = GetStackValue()
            except Exception:
                self.StackContainer.enable_updates()
                return
            if(start_address is None or end_address is None):
                self.StackContainer.enable_updates()
                return
            if self.followInReg == self.stack_pointer_name:
                follow_in_address = stack_pointer_value
            elif self.followInReg == self.base_pointer_name:
                follow_in_address = base_pointer_value
            else:
                follow_in_address = self.followInAddress
            if follow_in_address is None:
                return False

            # If the follow in address moves significantly, reset the viewer address
            if(follow_in_address < start_address + STACK_SIZE_ABOVE_MIN * self.bitnessSize or\
                    follow_in_address > end_address - STACK_SIZE_BELOW_MIN * self.bitnessSize):
                self.StackContainer.reset_address(follow_in_address,STACK_SIZE_ABOVE)
                self.StackValues.clear()
                self.StackvarDict.clear()
                self.reset_stkvar_marks()
                start_address,end_address = self.StackContainer.get_address_range()
            if(start_address is None or end_address is None):
                return


            self.add_new_data_above(follow_in_address, start_address)
            self.add_new_data_below(follow_in_address, end_address)


            # delete the lines that exceeds the limit
            lines_to_delete = (max((follow_in_address - start_address) // self.bitnessSize - STACK_SIZE_ABOVE_MAX, 0)) % 20
            for _ in range(lines_to_delete):
                self.StackContainer.del_line_at_end()

            lines_to_delete = (max((end_address - follow_in_address) // self.bitnessSize - STACK_SIZE_BELOW_MAX, 0)) % 20
            for _ in range(lines_to_delete):
                self.StackContainer.del_line_at_begin()

            # Update the currently displayed text
            start_address,end_address = self.StackContainer.get_address_range()
            self.get_stkvar_remark()
            self.set_stkvar_remark()
            self.refresh_stackvalues_dict(start_address,end_address)
            self.update_display_content(start_address,end_address)
            self.mark_stack_pointer(base_pointer_value,stack_pointer_value)


            self.StackContainer.roll_to_address(follow_in_address)
            self.StackContainer.enable_updates()


    def update_display_content(self, start_address, end_address):
        if(start_address is None or end_address is None):
            return
        if start_address is not None:
            for current_address in range(start_address,end_address +  self.bitnessSize,  self.bitnessSize):
                self.StackContainer.clear_item(current_address,0)
                if self.check_if_description_update(current_address):
                    current_value = self.idc_get_value(current_address)
                    self.StackContainer.edit_item(current_address,2,current_value)
                    self.set_stack_description(current_address,current_value)

    def check_if_description_update(self, current_address):
        if((current_address in self.StackvarDict and self.StackvarDict[current_address].VarInfoList is not None)\
            or current_address not in self.StackValues):
            return True

        stackvalue = [current_address] + self.StackValues[current_address]
        for i in range(0, len(stackvalue)-2):
            value = int.from_bytes(idc.get_bytes(stackvalue[i],self.bitnessSize), byteorder=self.endinness)
            if value != stackvalue[i+1]:
                return True
        if idc.get_bytes(stackvalue[-2],self.bitnessSize) != stackvalue[-1]:
            return True

        return False

    def refresh_stackvalues_dict(self,start_address,end_address):
        if(start_address is None or end_address is None):
            return
        tmp_dict = {address: Descriptions for address, Descriptions in self.StackValues.items() \
                    if start_address <= address <= end_address}
        self.StackValues = dict(tmp_dict)


    def set_stack_description(self,address,value,check_same=True):
        '''
        set the description column for address
        if the address isn't a stkvar then set the description
        else set its variables values

        check_same: 
        @if true: check if the variables values is same as the original values, and avoid edit to improve performance
        @if false, edit all variables values
        '''
        if(address not in self.StackvarDict or self.StackvarDict[address].VarInfoList is None):
            # value is not a stack var, or the stack var need a description
            Descriptions = GetValueDescription(value)
            self.StackContainer.clear_item(address,3)

            self.StackValues[address] = []
            if len(Descriptions) >= 1:
                for description in (Descriptions):
                    self.StackValues[address].append(description[3])
                self.StackValues[address].append(idc.get_bytes(self.StackValues[address][-1],self.bitnessSize))
            else:
                self.StackValues[address].append(idc.get_bytes(address,self.bitnessSize))

            COLOR_DICT = {
                T_VALUE:T_VALUE_SEG_COLOR,
                T_CODE:T_CODE_SEG_COLOR,
                T_DATA:T_DATA_SEG_COLOR,
                T_STACK:T_STACK_SEG_COLOR,
                T_BSS:T_BSS_SEG_COLOR,
                T_CONST:T_CONST_SEG_COLOR
            }

            descriptor_color = COLOR_DICT[Descriptions[0][0]]
            self.StackContainer.change_edit_color(address,2,descriptor_color)

            if Descriptions is not None:
                if len(Descriptions)> 1:
                    for i in range(len(Descriptions)-1):
                        self.StackContainer.insert_text(address,3,ARROW_SYMBOL,ARROW_SYMBOL_COLOR)

                        if Descriptions[i][2] != "":
                            self.StackContainer.insert_text(address,3,"("+Descriptions[i][1]+")",descriptor_color)

                        descriptor_color = COLOR_DICT[Descriptions[i+1][0]]
                        self.StackContainer.insert_text(address,3,Descriptions[i][2],descriptor_color)

                if Descriptions[-1][2] != "":
                    self.StackContainer.insert_text(address,3,".",ARROW_SYMBOL_COLOR)

                    if Descriptions[-1][2] != "":
                        self.StackContainer.insert_text(address,3,"("+Descriptions[-1][1]+")",descriptor_color)

                    if Descriptions[-1][0] == T_CODE:
                        descriptor_color = T_CODE_COLOR
                    else:
                        descriptor_color = T_DATA_COLOR
                    self.StackContainer.insert_text(address,3,Descriptions[-1][2],descriptor_color)
        else:
            # refresh the stack variables values
            self.StackContainer.change_edit_color(address,2,T_STACK_VAR_COLOR)
            varinfos = self.StackvarDict[address].VarInfoList
            var_texts = []

            is_changed = False

            for i,varinfo in enumerate(varinfos):
                varaddr = varinfo.addr
                varsize = varinfo.size
                varbytes = idc.get_bytes(varaddr,varsize)
                varvalue = int.from_bytes(varbytes,byteorder=CpuInfo.instance.endinness, signed=False)
                vartype = varinfo.type

                if(varvalue != self.StackvarDict[address].VarInfoList[i].value or not check_same):
                    is_changed = True
                if vartype.get_realtype() == 0:
                    varstr = ":"+ f"{varvalue:X} "
                else:
                    varstr = ":"+ConversionBytesToStr(varbytes,varsize,vartype)+" "
                var_texts.append([varinfo.name,STACK_VARIBLE_REMARK_COLOR])
                var_texts.append([varstr,STACK_VARIBLE_REMARK_COLOR])
                self.StackvarDict[address].VarInfoList[i].value = varvalue

            if is_changed:
                self.StackContainer.clear_item(address,3)
                for var_text in var_texts:
                    self.StackContainer.insert_text(address,3,var_text[0],var_text[1])



    def refresh_stackvar_dict(self,start_address):
        if self.StackvarDict is not None:
            tmp_dict = {}
            for address, remark in self.StackvarDict.items():
                if start_address <= remark.base_addr:
                    tmp_dict[address] = remark
                else:
                    self.StackContainer.clear_item(address,4)

            if tmp_dict is not None:
                self.StackvarDict = dict(tmp_dict)


    def get_stkvar_remark(self):
        ''' get stack varibles information and generate remarks '''
        start_address,end_address = self.StackContainer.get_address_range()
        if(start_address is None or end_address is None):
            return
        try:
            ip_reg_value = idaapi.get_reg_val(self.instruction_pointer_name)
            sp_reg_value = idaapi.get_reg_val(self.stack_pointer_name)
        except Exception:
            return

        _,func_frame_trace,_ = GetFunctionStackTrace()
        for stkvar_base_addr,func in func_frame_trace.items():
            func_name = get_func_name(func.start_ea)
            if stkvar_base_addr is not None:
                stkvar_dict = GetStkVar(func,stkvar_base_addr,self.bitnessSize)
                for current_address in range(start_address,end_address,self.bitnessSize):
                    if current_address < sp_reg_value:
                        self.StackContainer.clear_item(current_address,4)
                        continue
                    elif current_address in stkvar_dict:
                        # Currently stkvar has been added to StackvarDict
                        if(current_address in self.StackvarDict and self.StackvarDict[current_address].base_addr == stkvar_base_addr):
                            continue

                        if stkvar_dict[current_address][0].name == " r":
                            remark_text = f"Func {func_name}.{stkvar_base_addr:X} Return Address"
                            self.StackvarDict[current_address] = StackVarRemark\
                                (stkvar_base_addr,remark_text,STACK_RETURN_REMARK_COLOR,None)

                        elif stkvar_dict[current_address][0].name == " s":
                            remark_text = f"Func {func_name}.{stkvar_base_addr:X} Base Address"
                            self.StackvarDict[current_address] = StackVarRemark\
                                (stkvar_base_addr,remark_text,STACK_RETURN_REMARK_COLOR,None)

                        else:
                            remark_text_list = []
                            for varinfo in stkvar_dict[current_address]:
                                varname = varinfo.name
                                varaddr = varinfo.addr
                                varsize = varinfo.size
                                vartype = varinfo.type

                                if vartype.get_realtype() == 0:
                                    remark_text_list.append("{" + func_name +"}" +  varname)
                                else:
                                    remark_text_list.append("{" + func_name +"}("+ GetTypeName(vartype) +")" +  varname)


                                if  (varaddr % self.bitnessSize + varsize) > self.bitnessSize:
                                    for i in range((varaddr % self.bitnessSize + varsize) // self.bitnessSize):
                                        self.StackvarDict[varaddr + i * self.bitnessSize] = \
                                        StackVarRemark(stkvar_base_addr,f"({varname})",STACK_VARIBLE_REMARK_COLOR,[])

                            remark_text = ", ".join(remark_text_list)
                            self.StackvarDict[current_address] = StackVarRemark\
                                (stkvar_base_addr,remark_text,STACK_VARIBLE_REMARK_COLOR,stkvar_dict[current_address])
                    else:
                        continue

    def set_stkvar_remark(self):
        ''' set remark for stack variables '''
        if GetDbgStatus():
            sp_reg_value = idaapi.get_reg_val(self.stack_pointer_name)
            self.refresh_stackvar_dict(sp_reg_value)


        if self.StackvarDict is not None:
            for current_address in self.StackvarDict:
                stack_var_remark = self.StackvarDict[current_address]

                self.StackContainer.edit_item(current_address,4,stack_var_remark.remark_text)
                self.StackContainer.change_edit_color(current_address,4,stack_var_remark.remark_color)


    # use "self.StackContainer.reset_address" will make stkvar marks lost
    # the function used to reset these stkvar marks
    def reset_stkvar_marks(self):
        for address in self.StackvarDict:
            value = self.idc_get_value(address)
            # self.StackContainer.edit_item(address,2,value)
            self.set_stack_description(address,value,False)



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

    def follow_in_SP(self):
        self.followInReg = self.stack_pointer_name
        self.RefreshStackContainer()
        self.StackContainer.refresh_window()

    def follow_in_BP(self):
        self.followInReg = self.base_pointer_name
        self.RefreshStackContainer()
        self.StackContainer.refresh_window()

    def follow_in_address(self,addr):
        form = addr_input_form(addr)
        IsChange = form.Execute()
        if IsChange:
            self.followInReg = None
            self.followInAddress = form.inputaddr
            self.RefreshStackContainer()
            self.StackContainer.refresh_window()

    def reset_szie(self):
        global STACK_SIZE_ABOVE
        global STACK_SIZE_BELOW
        global STACK_SIZE_ABOVE_MAX
        global STACK_SIZE_BELOW_MAX

        form = size_set_form(STACK_SIZE_ABOVE,STACK_SIZE_BELOW)
        IsChange = form.Execute()

        if(IsChange and form.above_size is not None and form.below_size is not None):
            if(form.above_size > INPUT_MAX_STACK_SIZE or form.below_size > INPUT_MAX_STACK_SIZE):
                idaapi.warning("input too large")
                return False
            STACK_SIZE_ABOVE =  form.above_size
            STACK_SIZE_BELOW = form.below_size
            STACK_SIZE_ABOVE_MAX = STACK_SIZE_ABOVE + 20
            STACK_SIZE_BELOW_MAX = STACK_SIZE_BELOW + 20

            if GetDbgStatus():
                self.InitStackContainer()
                self.StackContainer.refresh_window()
            return True
        return False

    def OnClose(self, form):
        if self.hook:
            self.hook.unhook()




class size_set_form(idaapi.Form):
    def __init__(self,above_size, below_size):
        self.above_size = above_size
        self.below_size = below_size
        super().__init__(
        r'''
        {FormChangeCb}
        Reset the number of entries for StackViewer
        <Above : {_above}>
        <Below : {_below}>

        ''',
        {
        "FormChangeCb": self.FormChangeCb(self.OnFormChange),

        "_above": self.NumericInput(value = self.above_size, swidth = 30),
        "_below": self.NumericInput(value = self.below_size, swidth = 30),
        }
        )
        self.Compile()


    def OnFormChange(self,fid):
        if(fid in [self._above.id,self._below.id]):
            self.above_size = self.GetControlValue(self._above)
            self.below_size = self.GetControlValue(self._below)

        return 1


class addr_input_form(idaapi.Form):
    def __init__(self,inputaddr):
        self.inputaddr = inputaddr
        super().__init__(
        r'''
        {FormChangeCb}
        <Follow in address: {_addr}>
        ''',
        {
        "FormChangeCb": self.FormChangeCb(self.OnFormChange),

        "_addr": self.NumericInput(value = self.inputaddr, swidth = 30),
        }
        )
        self.Compile()

    def OnFormChange(self,fid):
        if fid == self._addr.id:
            self.inputaddr = self.GetControlValue(self._addr)

        return 1
