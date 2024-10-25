import idaapi
import idc


from PyQt5 import QtWidgets

import time


from StackView.Defines import *
from StackView.DbgStackInspector import *
from StackView.StackContainer import *
from StackView.Dbg_Hooks import *






class Sec_Viewer(idaapi.PluginForm):
    def __init__(self):
        super(Sec_Viewer, self).__init__()    # 初始化父类
        self.Bitness = CpuInfo.get_bitness()  # 位数
        self.bitnessSize = self.Bitness // 8

        self.base_pointer_name,self.stack_pointer_name = GetStackRegsName()

        self.CurrentTextDict = {}







    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)  
        self.InitGUI()


    def InitGUI(self):
        self.StackContainer = StackContainer(self.Bitness)

        if(GetDbgStatus()):
            self.StackContainer.backgroundColor = DEBUG_BACKGROUND_COLOR
            self.StackContainer.reset_QSS()


        self.hbox = QtWidgets.QVBoxLayout()
        self.hbox.setContentsMargins(0, 0, 0, 0)
        self.hbox.addWidget(self.StackContainer)
        # 设置父窗口的布局
        self.parent.setLayout(self.hbox)
        
        self.InitDbgHooks()
        self.InitStackContainer()

        
    def InitDbgHooks(self):

        def callbacks(operation):
            # 调试暂停
            if(operation == 0):
                self.RefreshStackContainer()

        self.hook = SecDebugHooks(callbacks)
        self.hook.hook()






    def idcgetvalue(self, address):
        if(self.Bitness == 64):
            return idc.get_qword(address)
        elif(self.Bitness == 32):
            return idc.get_wide_dword(address)




    # 初始化窗口
    def InitStackContainer(self):




        if(GetDbgStatus()):

            self.StackContainer.DisableUpdates()

            self.StackContainer.ClearAllLines()

            base_pointer_value, stack_pointer_value = GetStackValue()

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
          
            self.StackContainer.EditItem(base_pointer_value,0,self.base_pointer_name + "->")
            self.StackContainer.ChangeEditColor(base_pointer_value,0,STACK_POINTS_REGS_COLOR)
              
            self.StackContainer.EditItem(stack_pointer_value,0,self.stack_pointer_name + "->")
            self.StackContainer.ChangeEditColor(stack_pointer_value,0,STACK_POINTS_REGS_COLOR)

            self.StackContainer.RolltoAddress(stack_pointer_value)
            self.StackContainer.EnableUpdates()
            self.StackContainer.RefreshWindows()






    # 更新窗口信息
    def RefreshStackContainer(self):
        
        start_time = time.time()

                
        if(GetDbgStatus()):
            self.StackContainer.DisableUpdates()

            start_address,end_address = self.StackContainer.GetAddressRange()
            base_pointer_value, stack_pointer_value = GetStackValue()


            # 如果栈顶指针大幅移动，则重置栈窗口
            if(stack_pointer_value < start_address or stack_pointer_value > end_address):
                self.InitStackContainer()
                return
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
            lines_to_delete = max((stack_pointer_value - start_address) // self.bitnessSize - STACK_SIZE_ABOVE_MAX, 0)
            for _ in range(lines_to_delete):
                self.StackContainer.delLineAtEnd()

            lines_to_delete = max((end_address - stack_pointer_value) // self.bitnessSize - STACK_SIZE_BELOW_MAX, 0)
            for _ in range(lines_to_delete):
                self.StackContainer.delLineAtBegin()



            if(start_address != -1):





                # 删除旧数据
                for current_address in range(start_address,end_address +  self.bitnessSize,  self.bitnessSize):

                    # 删除指针信息
                    self.StackContainer.ClearItme(current_address,0)
                    current_value = self.idcgetvalue(current_address)
                    # 更新数据信息   

                    if(self.CurrentTextDict[current_address][0] != current_value or self.CurrentTextDict[current_address][1] !=  GetValueDescription(current_value)):
                        self.StackContainer.ClearItme(current_address,2)
                        self.StackContainer.ClearItme(current_address,3)
                        self.StackContainer.ClearItme(current_address,4)
                        self.StackContainer.ClearItme(current_address,5)
                        self.StackContainer.ClearItme(current_address,6)

                        self.StackContainer.EditItem(current_address,2,self.idcgetvalue(current_address))
                        self.SetStaclkDescription(current_address,current_value)




                



            # 重新加入指针信息            
            self.StackContainer.EditItem(base_pointer_value,0,self.base_pointer_name + "->")
            self.StackContainer.ChangeEditColor(base_pointer_value,0,STACK_POINTS_REGS_COLOR)
            
            self.StackContainer.EditItem(stack_pointer_value,0,self.stack_pointer_name + "->")
            self.StackContainer.ChangeEditColor(stack_pointer_value,0,STACK_POINTS_REGS_COLOR)

            self.StackContainer.RolltoAddress(stack_pointer_value)

            self.StackContainer.EnableUpdates()
            self.StackContainer.RefreshWindows()


        print("refresh consume: {:.5f}s".format(time.time() - start_time))




 
 

    def SetStaclkDescription(self,address,value):
        Descriptions = GetValueDescription(value)
        self.CurrentTextDict[address] = [value,Descriptions]

        






        COLOR_DICT = {
            T_VALUE:T_VALUE_COLOR,
            T_CODE:T_CODE_COLOR,
            T_DATA:T_DATA_COLOR,
            T_STACK:T_STACK_COLOR,
            T_BSS:T_BSS_COLOR,
            T_CONST:T_CONST_COLOR
        }




        
        for descriptor in Descriptions:
            if(descriptor[2] != ""):
                self.StackContainer.InsertText(address,3,ARROW_SYMBOL,ARROW_SYMBOL_COLOR)
                descriptor_color = COLOR_DICT[descriptor[0]]
                self.StackContainer.InsertText(address,3,"("+descriptor[1]+")",descriptor_color)
                self.StackContainer.InsertText(address,3,descriptor[2],descriptor_color)    









    # 
    def ClickEvent():
        pass





    def GetFuncInfo(self):
        pass




















    def OnClose(self, form):
        if self.hook:
            self.hook.unhook()
