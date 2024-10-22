import idaapi
import idc


from PyQt5 import QtWidgets



from StackView.Defines import *
from StackView.DbgGetStackValue import *
from StackView.StackContainer import *
from StackView.Dbg_Hooks import *






class Sec_Viewer(idaapi.PluginForm):
    def __init__(self):
        super(Sec_Viewer, self).__init__()    # 初始化父类
        self.Bitness = CpuInfo.get_bitness()  # 位数
        self.bitnessSize = self.Bitness // 8
        self.DbgStack = DbgGetStackValue()

        self.base_pointer_name =  self.DbgStack.base_pointer
        self.stack_pointer_name =  self.DbgStack.stack_pointer







    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)  
        self.InitGUI()


    def InitGUI(self):
        self.StackContainer = StackContainer(self.Bitness)

        if(self.DbgStack.GetDbgStatus()):
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
        if(self.DbgStack.GetDbgStatus()):

            base_pointer_value, stack_pointer_value = self.DbgStack.GetStackValue()

            # 以当前的的栈顶地址为基准开始初始化
            self.StackContainer.addLineAtEnd(stack_pointer_value,self.idcgetvalue(stack_pointer_value))
            self.StackContainer.ChangeEditColor(stack_pointer_value,1,STACK_ADDRESS_COLOR)


            # 从栈顶向上加入数据
            for i in range(1,STACK_SIZE_ABOVE):
                self.StackContainer.addLineAtBegin(None,self.idcgetvalue(stack_pointer_value - (i * self.bitnessSize)))
                self.StackContainer.ChangeEditColor(stack_pointer_value - (i * self.bitnessSize),1,STACK_ADDRESS_COLOR)


            # 从栈顶向下加入数据
            for i in range(1,STACK_SIZE_BELOW):

                self.StackContainer.addLineAtEnd(None,self.idcgetvalue(stack_pointer_value + (i * self.bitnessSize)))
                self.StackContainer.ChangeEditColor(stack_pointer_value + i * self.bitnessSize ,1,STACK_ADDRESS_COLOR)
            

            # 标记指针
            
            self.StackContainer.EditItem(stack_pointer_value,0,self.stack_pointer_name + "->")
            self.StackContainer.ChangeEditColor(stack_pointer_value,0,STACK_POINTS_REGS_COLOR)

            self.StackContainer.EditItem(base_pointer_value,0,self.base_pointer_name + "->")
            self.StackContainer.ChangeEditColor(base_pointer_value,0,STACK_POINTS_REGS_COLOR)
            
            






    # 更新窗口信息
    def RefreshStackContainer(self):

        
        if(self.DbgStack.GetDbgStatus()):

            start_address,end_address = self.StackContainer.GetAddressRange()
            base_pointer_value, stack_pointer_value = self.DbgStack.GetStackValue()


            # 如果栈顶指针大幅移动，则重置栈窗口
            if(stack_pointer_value < start_address or stack_pointer_value > end_address):
                self.InitStackContainer()

            # 如果栈顶指针减少，则向上添加新数据
            if(stack_pointer_value - start_address < STACK_SIZE_ABOVE * self.bitnessSize):
                for current_address in range(start_address - self.bitnessSize,stack_pointer_value - (STACK_SIZE_ABOVE + 1) * self.bitnessSize, -self.bitnessSize):
                    self.StackContainer.addLineAtBegin(None,self.idcgetvalue(current_address))
                    self.StackContainer.ChangeEditColor(current_address,1,STACK_ADDRESS_COLOR)

                    self.StackContainer.delLineAtEnd()

            # 如果栈顶指针增大，则向下添加新数据
            if(end_address - stack_pointer_value < STACK_SIZE_BELOW * self.bitnessSize):
                print("start:",end_address + self.bitnessSize)
                print("end:",stack_pointer_value + (STACK_SIZE_BELOW + 1) * self.bitnessSize)
                for current_address in range(end_address + self.bitnessSize, stack_pointer_value + (STACK_SIZE_BELOW + 1) * self.bitnessSize, self.bitnessSize):
                    self.StackContainer.addLineAtEnd(None,self.idcgetvalue(current_address))
                    self.StackContainer.ChangeEditColor(current_address,1,STACK_ADDRESS_COLOR)

                    self.StackContainer.delLineAtBegin()






            if(start_address != -1):





                # 删除旧数据
                for current_address in range(start_address,end_address +  self.bitnessSize,  self.bitnessSize):

                    # 删除指针信息
                    self.StackContainer.ClearItme(current_address,0)

                    # 更新数据信息   
                    PreviousValue = self.StackContainer.GetItemText(current_address,2)
                    if( isinstance(PreviousValue,str) and int(PreviousValue,16) != self.idcgetvalue(current_address)):
                        self.StackContainer.ClearItme(current_address,2)
                        self.StackContainer.ClearItme(current_address,3)
                        self.StackContainer.ClearItme(current_address,4)
                        self.StackContainer.ClearItme(current_address,5)

                        self.StackContainer.EditItem(current_address,2,self.idcgetvalue(current_address))





                



            # 重新加入指针信息
            self.StackContainer.EditItem(stack_pointer_value,0,self.stack_pointer_name + "->")
            self.StackContainer.ChangeEditColor(stack_pointer_value,0,STACK_POINTS_REGS_COLOR)

            self.StackContainer.EditItem(base_pointer_value,0,self.base_pointer_name + "->")
            self.StackContainer.ChangeEditColor(base_pointer_value,0,STACK_POINTS_REGS_COLOR)
            
            

    def OnClose(self, form):
        if self.hook:
            self.hook.unhook()
