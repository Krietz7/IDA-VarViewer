import idaapi
import idc


from PyQt5 import QtWidgets



from StackView.Defines import *
from StackView.DbgGetStackValue import *
from StackView.StackContainer import StackContainer






class Sec_Viewer(idaapi.PluginForm):
    def __init__(self):
        super(Sec_Viewer, self).__init__()    # 初始化父类
        self.Bitness = CpuInfo.get_bitness()  # 位数
        self.DbgStack = DbgGetStackValue()









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
        
        self.InitStackContainer()

        


    # 初始化窗口
    def InitStackContainer(self):
        if(self.DbgStack.GetDbgStatus()):
            base_pointer_value, stack_pointer_value = self.DbgStack.GetStackValue()



            # 以当前的的栈顶地址为基准开始初始化
            self.StackContainer.addLineAtEnd(stack_pointer_value,idc.get_qword(stack_pointer_value))
            self.StackContainer.ChangeEditColor(stack_pointer_value,2,"red")

            for i in range(1,STACK_SIZE_ABOVE):
                self.StackContainer.addLineAtBegin(None,idc.get_qword(stack_pointer_value - (i * self.Bitness // 8)))
                self.StackContainer.ChangeEditColor(stack_pointer_value - (i * self.Bitness // 8),2,STACK_ADDRESS_COLOR)


            for i in range(1,STACK_SIZE_BELOW):

                self.StackContainer.addLineAtEnd(None,idc.get_qword(stack_pointer_value + (i * self.Bitness // 8)))
                self.StackContainer.ChangeEditColor(stack_pointer_value + i * 8 ,2,STACK_ADDRESS_COLOR)
            
                


        pass
