import idaapi
import idc


from PyQt5 import QtWidgets

import time
import string



from StackView.DbgStackInspector import *
from StackView.QtContainers.StackContainer import *
from StackView.Dbg_Hooks import *
from StackView.FunctionInfo import *





class StackViewer(idaapi.PluginForm):
    def __init__(self):
        super(StackViewer, self).__init__()    # 初始化父类
        self.Bitness = CPUinfo.bitness  # 位数
        self.bitnessSize = self.Bitness // 8
        self.endinness = CPUinfo.endinness
        self.base_pointer_name,self.stack_pointer_name,self.two_pointer_name,self.instruction_pointer_name = GetStackRegsName()

        self.InitSuccess = False

        self.CurrentTextDict = {} # 记录当前显示的文本数据，判断是否需要更新
        self.FunctionInfoDict = {}
        self.StackvarDict = {}

        self.followInReg = self.stack_pointer_name
        self.followInAddress = 0


    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)  
        self.InitGUI()


    def InitGUI(self):



        self.hbox = QtWidgets.QVBoxLayout()
        self.StackContainer = StackContainer(self.parent,self.Bitness,self)
        self.hbox.setContentsMargins(0, 0, 0, 0)
        self.hbox.addWidget(self.StackContainer)
        # 设置父窗口的布局
        self.parent.setLayout(self.hbox)
        

        
        if(GetDbgStatus()):
            self.StackContainer.backgroundColor = DEBUG_BACKGROUND_COLOR
            self.StackContainer.reset_QSS()
            self.StackContainer.RefreshWindow()

        self.InitDbgHooks()
        
        if(GetDbgStatus()):
            self.InitStackContainer()
            self.StackContainer.RefreshWindow()

    def InitDbgHooks(self):

        def callbacks(operation):
            # 调试暂停
            if(operation == 0):
                if(not self.InitSuccess):
                    self.InitStackContainer()
                    self.StackContainer.RefreshWindow()       

                # 窗口在前台显示
                elif(self.StackContainer.isVisible() and self.InitSuccess):
                    
                    self.RefreshStackContainer()
                    self.StackContainer.RefreshWindow()



        self.hook = DebugHooks(callbacks)
        self.hook.hook()






    def idcgetvalue(self, address):
        if(self.Bitness == 64):
            return idc.get_qword(address)
        elif(self.Bitness == 32):
            return idc.get_wide_dword(address)



    def initStackLine(self,address,is_end):
        if(is_end):
            self.StackContainer.addLineAtEnd(address,self.idcgetvalue(address))
        else:
            self.StackContainer.addLineAtBegin(address,self.idcgetvalue(address))

        self.StackContainer.ChangeEditColor(address,1,STACK_ADDRESS_COLOR)
        self.SetStaclkDescription(address,self.idcgetvalue(address))

    def markStackPointer(self,base_pointer_value,stack_pointer_value):
        
        if(base_pointer_value != stack_pointer_value):
            self.StackContainer.EditItem(base_pointer_value,0,self.base_pointer_name + "->")
            self.StackContainer.ChangeEditColor(base_pointer_value,0,STACK_POINTS_REGS_COLOR)
            
            self.StackContainer.EditItem(stack_pointer_value,0,self.stack_pointer_name + "->")
            self.StackContainer.ChangeEditColor(stack_pointer_value,0,STACK_POINTS_REGS_COLOR)
        else:
            self.StackContainer.EditItem(stack_pointer_value,0,self.two_pointer_name + ">")
            self.StackContainer.ChangeEditColor(stack_pointer_value,0,STACK_POINTS_REGS_COLOR)      






    def addNewDataAbove(self, stack_pointer_value, start_address):
        if(stack_pointer_value - start_address < STACK_SIZE_ABOVE_MAX * self.bitnessSize):
            load_count = 0
            for current_address in range(start_address - self.bitnessSize,
                                        stack_pointer_value - (STACK_SIZE_ABOVE_MAX + 1) * self.bitnessSize,\
                                        - self.bitnessSize):
                load_count += 1
                if(load_count >= ONCE_LOAD_SIZE):
                    break
                self.initStackLine(current_address,False)



    def addNewDataBelow(self, stack_pointer_value, end_address):
        if end_address - stack_pointer_value < STACK_SIZE_BELOW_MAX * self.bitnessSize:
            load_count = 0
            for current_address in range(end_address + self.bitnessSize,\
                                        stack_pointer_value + (STACK_SIZE_BELOW_MAX + 1) * self.bitnessSize,\
                                        self.bitnessSize):
                load_count += 1
                if load_count >= ONCE_LOAD_SIZE:
                    break
                self.initStackLine(current_address, True)


    def updateDisplayContent(self, start_address, end_address):
        if(start_address == None or end_address == None):
            return
        if(start_address != None):
            # 删除旧数据
            for current_address in range(start_address,end_address +  self.bitnessSize,  self.bitnessSize):
                # 删除指针信息
                self.StackContainer.ClearItem(current_address,0)
                current_value = self.idcgetvalue(current_address)
                if((current_address not in self.CurrentTextDict) or (self.CurrentTextDict[current_address][0] != current_value)\
                    or (self.CurrentTextDict[current_address][1] !=  GetValueDescription(current_value))
                    or current_address in self.StackvarDict):                        
                    self.StackContainer.ClearItem(current_address,2)
                    self.StackContainer.ClearItem(current_address,3)
                    self.StackContainer.EditItem(current_address,2,self.idcgetvalue(current_address))
                    self.SetStaclkDescription(current_address,current_value)

    # 初始化窗口
    def InitStackContainer(self):
        # start_time = time.time()
        if(GetDbgStatus()):
            self.StackContainer.DisableUpdates()
            self.StackContainer.ClearAllLines()

            try:
                base_pointer_value, stack_pointer_value = GetStackValue()
            except:
                # 程序处于暂停状态，停止初始化
                self.StackContainer.EnableUpdates()
                return
            
            if(self.followInReg == self.stack_pointer_name):
                    follow_in_address = stack_pointer_value
            elif(self.followInReg == self.base_pointer_name):
                    follow_in_address = base_pointer_value
            else:
                follow_in_address = self.followInAddress


            # 以followIn_address为基准开始初始化
            self.initStackLine(follow_in_address,True)
            # 从栈顶向上加入数据
            for i in range(1,STACK_SIZE_ABOVE):
                current_address = follow_in_address - (i * self.bitnessSize)
                self.initStackLine(current_address,False)
            # 从栈顶向下加入数据
            for i in range(1,STACK_SIZE_BELOW):
                current_address = follow_in_address + (i * self.bitnessSize)
                self.initStackLine(current_address,True)

            self.SetRemark()


            # 标记指针
            self.markStackPointer(base_pointer_value,stack_pointer_value)
            
            self.StackContainer.RolltoAddress(follow_in_address)
            self.StackContainer.EnableUpdates()
            self.StackContainer.RefreshWindow()
            


            # 标记初始化完成
            self.InitSuccess = True
        # print("Init consume: {:.5f}s".format(time.time() - start_time))

    # 更新窗口信息
    def RefreshStackContainer(self):
        # start_time = time.time()
        if(GetDbgStatus()):
            self.StackContainer.DisableUpdates()

            try:
                start_address,end_address = self.StackContainer.GetAddressRange()
                base_pointer_value, stack_pointer_value = GetStackValue()
            except:
                self.StackContainer.EnableUpdates()
                return
            if(start_address == None or end_address == None):
                self.StackContainer.EnableUpdates()
                return


            if(self.followInReg == self.stack_pointer_name):
                    follow_in_address = stack_pointer_value
            elif(self.followInReg == self.base_pointer_name):
                    follow_in_address = base_pointer_value
            else:
                follow_in_address = self.followInAddress


            # 如果栈顶指针大幅移动，则重置地址
            if(follow_in_address < start_address + STACK_SIZE_ABOVE_MIN * self.bitnessSize or follow_in_address > end_address - STACK_SIZE_BELOW_MIN * self.bitnessSize):
                self.StackContainer.ResetAddress(follow_in_address,STACK_SIZE_ABOVE)
                self.CurrentTextDict.clear()
                start_address,end_address = self.StackContainer.GetAddressRange()
            if(start_address == None or end_address == None):
                return

            # 如果栈顶指针减少，则向上添加新数据
            self.addNewDataAbove(follow_in_address, start_address)
            # 如果栈顶指针增大，则向下添加新数据
            self.addNewDataBelow(follow_in_address, end_address)

            # 如果数据过大，删除超出限制的数据
            lines_to_delete = (max((follow_in_address - start_address) // self.bitnessSize - STACK_SIZE_ABOVE_MAX, 0)) % 20
            for _ in range(lines_to_delete):
                self.StackContainer.delLineAtEnd()

            lines_to_delete = (max((end_address - follow_in_address) // self.bitnessSize - STACK_SIZE_BELOW_MAX, 0)) % 20
            for _ in range(lines_to_delete):
                self.StackContainer.delLineAtBegin()

            # 更新当前显示的地址范围
            start_address,end_address = self.StackContainer.GetAddressRange()
            self.SetRemark()
            self.RefreshCurrentTextDict(start_address,end_address)
            self.updateDisplayContent(start_address,end_address)

            # 重新加入指针信息            
            self.markStackPointer(base_pointer_value,stack_pointer_value)

            self.StackContainer.RolltoAddress(follow_in_address)
            self.StackContainer.EnableUpdates()
            self.StackContainer.RefreshWindow()
        # print("refresh consume: {:.5f}s".format(time.time() - start_time))











    def RefreshCurrentTextDict(self,start_address,end_address):
        if(start_address == None or end_address == None):
            return
        tmp_dict = {address: Descriptions for address, Descriptions in self.CurrentTextDict.items() \
                    if start_address <= address <= end_address}
        self.CurrentTextDict = dict(tmp_dict)
 

    def SetStaclkDescription(self,address,value):
        if(address not in self.StackvarDict or self.StackvarDict[address][3] == None):
            Descriptions = GetValueDescription(value)
            self.CurrentTextDict[address] = [value,Descriptions]

            COLOR_DICT = {
                T_VALUE:T_VALUE_SEG_COLOR,
                T_CODE:T_CODE_SEG_COLOR,
                T_DATA:T_DATA_SEG_COLOR,
                T_STACK:T_STACK_SEG_COLOR,
                T_BSS:T_BSS_SEG_COLOR,
                T_CONST:T_CONST_SEG_COLOR
            }

            descriptor_color = COLOR_DICT[Descriptions[0][0]]
            self.StackContainer.ChangeEditColor(address,2,descriptor_color)
            
            if(Descriptions != None):
                if(len(Descriptions)> 1):
                    for i in range(len(Descriptions)-1):
                        self.StackContainer.InsertText(address,3,ARROW_SYMBOL,ARROW_SYMBOL_COLOR)

                        if(Descriptions[i][2] != ""):
                            self.StackContainer.InsertText(address,3,"("+Descriptions[i][1]+")",descriptor_color)

                        descriptor_color = COLOR_DICT[Descriptions[i+1][0]]
                        self.StackContainer.InsertText(address,3,Descriptions[i][2],descriptor_color)    


                if(Descriptions[-1][2] != ""):
                    self.StackContainer.InsertText(address,3,".",ARROW_SYMBOL_COLOR)

                    if(Descriptions[-1][2] != ""):
                        self.StackContainer.InsertText(address,3,"("+Descriptions[-1][1]+")",descriptor_color)

                    if(Descriptions[-1][0] == T_CODE):
                        descriptor_color = T_CODE_COLOR
                    else:
                        descriptor_color = T_DATA_COLOR
                    self.StackContainer.InsertText(address,3,Descriptions[-1][2],descriptor_color)    
        else:
            self.StackContainer.ChangeEditColor(address,2,T_STACK_VAR_COLOR)
            varinfo = self.StackvarDict[address][3]
            for i in range(0,len(varinfo),3):
                self.StackContainer.InsertText(address,3,varinfo[i+0],STACK_VARIBLE_REMARK_COLOR)
                varbytes = idc.get_bytes(varinfo[i+2],varinfo[i+1])
                varvalue = int.from_bytes(varbytes,byteorder=CPUinfo.endinness, signed=False)
                varstr = ":"+hex(varvalue)+" "
                self.StackContainer.InsertText(address,3,varstr,STACK_VARIBLE_REMARK_COLOR)


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



    def FollowInSP(self):
        self.followInReg = self.stack_pointer_name
        self.RefreshStackContainer()
        self.StackContainer.RefreshWindow()

    def FollowInBP(self):
        self.followInReg = self.base_pointer_name
        self.RefreshStackContainer()
        self.StackContainer.RefreshWindow()


    def FollowInAddress(self,addr):

        form = addr_input_form(addr)
        IsChange = form.Execute()
        if(IsChange):
            self.followInReg = None
            self.followInAddress = form.inputaddr
            self.RefreshStackContainer()
            self.StackContainer.RefreshWindow()




    def ResetSize(self):
        global STACK_SIZE_ABOVE
        global STACK_SIZE_BELOW
        global STACK_SIZE_ABOVE_MAX
        global STACK_SIZE_BELOW_MAX

        form = size_set_form(STACK_SIZE_ABOVE,STACK_SIZE_BELOW)
        IsChange = form.Execute()

        if(IsChange and form.above_size != None and form.below_size != None):
            STACK_SIZE_ABOVE =  form.above_size
            STACK_SIZE_BELOW = form.below_size
            STACK_SIZE_ABOVE_MAX = STACK_SIZE_ABOVE + 20
            STACK_SIZE_BELOW_MAX = STACK_SIZE_BELOW + 20

            if(GetDbgStatus()):
                self.InitStackContainer()
                self.StackContainer.RefreshWindow()
                








    def SetRemark(self):
        if(GetDbgStatus()):
            self.SetStkVarRemark()
            sp_reg_value = idaapi.get_reg_val(self.stack_pointer_name)
            self.RefreshStackvarDict(sp_reg_value)


        if(self.StackvarDict != None):
            for current_address in self.StackvarDict.keys():
                _,remark_text,color,_ = self.StackvarDict[current_address]
                self.StackContainer.EditItem(current_address,4,remark_text)
                self.StackContainer.ChangeEditColor(current_address,4,color)


    def RefreshStackvarDict(self,start_address):
        if(self.StackvarDict != None):
            tmp_dict = {}
            for address, remark in self.StackvarDict.items():
                if (start_address <= remark[0]):
                    tmp_dict[address] = remark  
                else:
                    self.StackContainer.ClearItem(address,4)

            if(tmp_dict != None):
                self.StackvarDict = dict(tmp_dict)



    def SetStkVarRemark(self,stkvar_base_addr = None):
        start_address,end_address = self.StackContainer.GetAddressRange()
        if(start_address == None or end_address == None):
            return
        try:
            ip_reg_value = idaapi.get_reg_val(self.instruction_pointer_name)
            sp_reg_value = idaapi.get_reg_val(self.stack_pointer_name)
        except:
            return 


        func = ida_funcs.get_fchunk(ip_reg_value)
        func_name = ida_funcs.get_func_name(ip_reg_value)


        stkvar_base_addr = GetFrameBaseAddress(func,ip_reg_value, sp_reg_value,self.Bitness,self.endinness)
        if(stkvar_base_addr != None):
            stkvar_dict = GetstkvarAddress(func,stkvar_base_addr,self.bitnessSize)
            for current_address in range(start_address,end_address,self.bitnessSize):
                if(current_address < sp_reg_value):
                    self.StackContainer.ClearItem(current_address,4)
                    continue    
                elif(current_address in stkvar_dict):
                    _ = None
                    if(stkvar_dict[current_address][0] == " r"):
                        remark_text = "Func " +  func_name + " Return Address"
                        self.StackvarDict[current_address] = [stkvar_base_addr,remark_text,STACK_RETURN_REMARK_COLOR,_]

                    elif(stkvar_dict[current_address][0] == " s"):
                        remark_text = "Func " +  func_name + " Base Address"
                        self.StackvarDict[current_address] = [stkvar_base_addr,remark_text,STACK_RETURN_REMARK_COLOR,_]

                    else:
                        if(len(stkvar_dict[current_address]) == 3):
                            remark_text = "(" + func_name +")" +  stkvar_dict[current_address][0]  # + "(size: " + str(stkvar_dict[current_address][1]) + ")"
                            self.StackvarDict[current_address] = [stkvar_base_addr,remark_text,STACK_VARIBLE_REMARK_COLOR,stkvar_dict[current_address]]

                        else:
                            self.StackContainer.ClearItem(current_address,4)
                            remark_text = ""
                            for i in range(0,len(stkvar_dict[current_address]),3):
                                remark_text += stkvar_dict[current_address][i+0] + "(" + hex(stkvar_dict[current_address][i+2]) + " size: " + str(stkvar_dict[current_address][i+1]) + ")"
                                self.StackvarDict[current_address] = [stkvar_base_addr,remark_text,STACK_VARIBLE_REMARK_COLOR,stkvar_dict[current_address]]
                    
                else:
                    continue

    def OnClose(self, form):
        if self.hook:
            self.hook.unhook()




class size_set_form(idaapi.Form):
    def __init__(self,above_size, below_size):
        
        self.above_size = above_size
        self.below_size = below_size
        
        super(size_set_form, self).__init__(
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
        self.inputaddr = inputaddr;
        super(addr_input_form, self).__init__(
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
        if(fid == self._addr.id):
            self.inputaddr = self.GetControlValue(self._addr)

        return 1