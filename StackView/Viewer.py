import idaapi
import idc


from PyQt5 import QtWidgets



from StackView.Defines import *
from StackView.DbgGetStackValue import DbgGetStackValue
from StackView.StackContainer import StackContainer






class Sec_Viewer(idaapi.PluginForm):
    def __init__(self):
        super(Sec_Viewer, self).__init__()    # 初始化父类
        self.DbgStack = DbgGetStackValue()






    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)  
        self.InitGUI()


    def InitGUI(self):
    
        self.StackContainer = StackContainer()

        if(self.DbgStack.GetDbgStatus()):
            self.StackContainer.backgroundColor = DEBUG_BACKGROUND_COLOR
            self.StackContainer.reset_QSS()


        self.hbox = QtWidgets.QVBoxLayout()
        self.hbox.setContentsMargins(0, 0, 0, 0)
        self.hbox.addWidget(self.StackContainer)
        # 设置父窗口的布局
        self.parent.setLayout(self.hbox)
        
        self.InitStackContainer()

        



    def InitStackContainer(self):
        if(self.DbgStack.GetDbgStatus()):
            base_pointer_value, stack_pointer_value = self.DbgStack.GetStackValue()
            for i in range(INIT_STACK_SIZE):

                self.StackContainer.addLineAtBegin(base_pointer_value-i*8,idc.get_qword(base_pointer_value-i*8))
            
                self.StackContainer.ChangeEditColor(base_pointer_value-i*8,2,"blue")
            



        pass
