import idaapi
import idc


from PyQt5 import QtWidgets

import time
import string


from StackView.Defines import *
from StackView.DbgStackInspector import *
from StackView.StackContainer import *
from StackView.Dbg_Hooks import *
from StackView.FunctionInfo import *





class Sec_Viewer(idaapi.PluginForm):
    def __init__(self):
        super(Sec_Viewer, self).__init__()    # 初始化父类
        self.Bitness = SEC_cpu_info.bitness  # 位数
        self.bitnessSize = self.Bitness // 8
        self.endinness = SEC_cpu_info.endinness
        self.base_pointer_name,self.stack_pointer_name,self.two_pointer_name,self.instruction_pointer_name = GetStackRegsName()

        self.InitSuccess = False

        self.CurrentTextDict = {} # 记录当前显示的文本数据，判断是否需要更新
        self.FunctionInfoDict = {}





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

        self.InitDbgHooks()
        
        if(GetDbgStatus()):
            self.InitStackContainer()
            self.SetRemark()


    def InitDbgHooks(self):

        def callbacks(operation):
            # 调试暂停
            if(operation == 0):
                if(not self.InitSuccess):
                    self.InitStackContainer()
                    
                # 窗口在前台显示
                elif(self.StackContainer.isVisible() and self.InitSuccess):
                    
                    self.RefreshStackContainer()
                    self.SetRemark()
                    self.StackContainer.RefreshWindow()




        self.hook = SecDebugHooks(callbacks)
        self.hook.hook()






    def idcgetvalue(self, address):
        if(self.Bitness == 64):
            return idc.get_qword(address)
        elif(self.Bitness == 32):
            return idc.get_wide_dword(address)



    # 初始化窗口
    def InitStackContainer(self):

        # start_time = time.time()


        if(GetDbgStatus()):

            self.StackContainer.DisableUpdates()

            self.StackContainer.ClearAllLines()

            try:
                base_pointer_value, stack_pointer_value = GetStackValue()
            except:
                self.StackContainer.EnableUpdates()
                return
            
            # 以当前的的栈顶地址为基准开始初始化
            self.StackContainer.addLineAtEnd(stack_pointer_value,self.idcgetvalue(stack_pointer_value))
            self.StackContainer.ChangeEditColor(stack_pointer_value,1,STACK_ADDRESS_COLOR)
            self.SetStaclkDescription(stack_pointer_value,self.idcgetvalue(stack_pointer_value))


            # 从栈顶向上加入数据
            for i in range(1,STACK_SIZE_ABOVE):
                current_address = stack_pointer_value - (i * self.bitnessSize)
                current_value = self.idcgetvalue(current_address)
                self.StackContainer.addLineAtBegin(None,current_value)
                self.StackContainer.ChangeEditColor(current_address,1,STACK_ADDRESS_COLOR)
                self.SetStaclkDescription(current_address,current_value)


            # 从栈顶向下加入数据
            for i in range(1,STACK_SIZE_BELOW):
                current_address = stack_pointer_value + (i * self.bitnessSize)
                current_value = self.idcgetvalue(current_address)
                self.StackContainer.addLineAtEnd(None,current_value)
                self.StackContainer.ChangeEditColor(current_address,1,STACK_ADDRESS_COLOR)
                self.SetStaclkDescription(current_address,current_value)
            

            # 标记指针
          
            if(base_pointer_value != stack_pointer_value):
                self.StackContainer.EditItem(base_pointer_value,0,self.base_pointer_name + "->")
                self.StackContainer.ChangeEditColor(base_pointer_value,0,STACK_POINTS_REGS_COLOR)
                
                self.StackContainer.EditItem(stack_pointer_value,0,self.stack_pointer_name + "->")
                self.StackContainer.ChangeEditColor(stack_pointer_value,0,STACK_POINTS_REGS_COLOR)
            else:
                self.StackContainer.EditItem(stack_pointer_value,0,self.two_pointer_name + ">")
                self.StackContainer.ChangeEditColor(stack_pointer_value,0,STACK_POINTS_REGS_COLOR)      






            self.StackContainer.RolltoAddress(stack_pointer_value)
            self.StackContainer.EnableUpdates()
            self.StackContainer.RefreshWindow()

            self.InitSuccess = True
            

        # print("Init consume: {:.5f}s".format(time.time() - start_time))





    # 更新窗口信息
    def RefreshStackContainer(self):
        
        # start_time = time.time()

                
        if(GetDbgStatus()):
            self.StackContainer.DisableUpdates()

            start_address,end_address = self.StackContainer.GetAddressRange()

            try:
                base_pointer_value, stack_pointer_value = GetStackValue()
            except:
                self.StackContainer.EnableUpdates()
                return

            # 如果栈顶指针大幅移动，则重置地址
            if(stack_pointer_value < start_address + STACK_SIZE_ABOVE_MIN * self.bitnessSize or stack_pointer_value > end_address - STACK_SIZE_BELOW_MIN * self.bitnessSize):
                self.StackContainer.ResetAddress(stack_pointer_value)
                self.CurrentTextDict.clear()
                start_address,end_address = self.StackContainer.GetAddressRange()

            # 如果栈顶指针减少，则向上添加新数据
            if(stack_pointer_value - start_address < STACK_SIZE_ABOVE_MAX * self.bitnessSize):
                load_count = 0
                for current_address in range(start_address - self.bitnessSize,stack_pointer_value - (STACK_SIZE_ABOVE_MAX + 1) * self.bitnessSize, - self.bitnessSize):
                    load_count += 1
                    if(load_count >= ONCE_LOAD_SIZE):
                        break
                    current_value = self.idcgetvalue(current_address)
                    self.StackContainer.addLineAtBegin(None,current_value)
                    self.StackContainer.ChangeEditColor(current_address,1,STACK_ADDRESS_COLOR)
                    self.SetStaclkDescription(current_address,current_value)

            
            # 如果栈顶指针增大，则向下添加新数据
            if(end_address - stack_pointer_value < STACK_SIZE_BELOW_MAX * self.bitnessSize):
                load_count = 0
                for current_address in range(end_address + self.bitnessSize, stack_pointer_value + (STACK_SIZE_BELOW_MAX + 1) * self.bitnessSize, self.bitnessSize):
                    load_count += 1
                    if(load_count >= ONCE_LOAD_SIZE):
                        break
                    current_value = self.idcgetvalue(current_address)
                    self.StackContainer.addLineAtEnd(None,current_value)
                    self.StackContainer.ChangeEditColor(current_address,1,STACK_ADDRESS_COLOR)
                    self.SetStaclkDescription(current_address,current_value)

            # 如果数据过大，删除超出限制的数据
            lines_to_delete = (max((stack_pointer_value - start_address) // self.bitnessSize - STACK_SIZE_ABOVE_MAX, 0)) % 20
            for _ in range(lines_to_delete):
                self.StackContainer.delLineAtEnd()


            lines_to_delete = (max((end_address - stack_pointer_value) // self.bitnessSize - STACK_SIZE_BELOW_MAX, 0)) % 20
            for _ in range(lines_to_delete):
                self.StackContainer.delLineAtBegin()


            # 更新当前显示的地址范围
            start_address,end_address = self.StackContainer.GetAddressRange()
            self.RefreshCurrentTextDict(start_address,end_address)
            if(start_address != -1):
                # 删除旧数据
                for current_address in range(start_address,end_address +  self.bitnessSize,  self.bitnessSize):

                    # 删除指针信息
                    self.StackContainer.ClearItme(current_address,0)
                    current_value = self.idcgetvalue(current_address)

                    if((current_address not in self.CurrentTextDict) or (self.CurrentTextDict[current_address][0] != current_value) or (self.CurrentTextDict[current_address][1] !=  GetValueDescription(current_value))):                        
                        
                        self.StackContainer.ClearItme(current_address,2)
                        self.StackContainer.ClearItme(current_address,3)

                        self.StackContainer.EditItem(current_address,2,self.idcgetvalue(current_address))
                        self.SetStaclkDescription(current_address,current_value)

            # 重新加入指针信息            
            if(base_pointer_value != stack_pointer_value):
                self.StackContainer.EditItem(base_pointer_value,0,self.base_pointer_name + "->")
                self.StackContainer.ChangeEditColor(base_pointer_value,0,STACK_POINTS_REGS_COLOR)
                
                self.StackContainer.EditItem(stack_pointer_value,0,self.stack_pointer_name + "->")
                self.StackContainer.ChangeEditColor(stack_pointer_value,0,STACK_POINTS_REGS_COLOR)
            else:
                self.StackContainer.EditItem(stack_pointer_value,0,self.two_pointer_name + ">")
                self.StackContainer.ChangeEditColor(stack_pointer_value,0,STACK_POINTS_REGS_COLOR)      



            self.StackContainer.RolltoAddress(stack_pointer_value)

            self.StackContainer.EnableUpdates()
            self.StackContainer.RefreshWindow()


        # print("refresh consume: {:.5f}s".format(time.time() - start_time))




    def RefreshCurrentTextDict(self,start_address,end_address):
        tmp_dict =  {address: Descriptions for address, Descriptions in self.CurrentTextDict.items() if start_address <= address <= end_address}
        self.CurrentTextDict = dict(tmp_dict)
 

    def SetStaclkDescription(self,address,value):
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



    def SetRemark(self):
        self.SetStkVarRemark()









    def SetStkVarRemark(self,stkvar_base_addr = None):
        start_address,end_address = self.StackContainer.GetAddressRange()
        
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
                    self.StackContainer.ClearItme(current_address,4)
                    continue    
                elif(current_address in stkvar_dict):

                    if(stkvar_dict[current_address][0] == " r"):
                        remark_text = "Func " +  func_name + " Return Address"
                        self.StackContainer.EditItem(current_address,4,remark_text)
                        self.StackContainer.ChangeEditColor(current_address,4,STACK_RETURN_REMARK_COLOR)
                    elif(stkvar_dict[current_address][0] == " s"):
                        remark_text = "Func " +  func_name + " Func Base Address"
                        self.StackContainer.EditItem(current_address,4,remark_text)
                        self.StackContainer.ChangeEditColor(current_address,4,STACK_BASE_REMARK_COLOR)

                    else:
                        if(len(stkvar_dict[current_address]) == 3):
                            remark_text = "(" + func_name +")" +  stkvar_dict[current_address][0]  # + "(size: " + str(stkvar_dict[current_address][1]) + ")"
                            self.StackContainer.EditItem(current_address,4,remark_text)
                            self.StackContainer.ChangeEditColor(current_address,4,STACK_VARIBLE_REMARK_COLOR)
                        else:
                            self.StackContainer.ClearItme(current_address,4)
                            for i in range(0,len(stkvar_dict[current_address]),3):
                                remark_text = stkvar_dict[current_address][i+0] + "(" + hex(stkvar_dict[current_address][i+2]) + " size: " + str(stkvar_dict[current_address][i+1]) + ")"
                                self.StackContainer.InsertText(current_address,4,remark_text)
                                self.StackContainer.ChangeEditColor(current_address,4,STACK_VARIBLE_REMARK_COLOR)

                    
                else:
                    continue















































    def OnClose(self, form):
        if self.hook:
            self.hook.unhook()
