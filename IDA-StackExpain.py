import idaapi


from PyQt5 import QtGui, QtCore, QtWidgets
from PyQt5.QtCore import Qt

#@#
import sys
sys.path.append("F:\\Projects\\IDA-StackAnnotation")
#@#

from StackView.Defines import *
from StackView.StackViewer import *
from StackView.VariableViewer import *

class MenuContext(idaapi.action_handler_t):

    @classmethod
    def get_name(self):
        return self.__name__

    @classmethod
    def get_label(self):
        return self.label

    @classmethod
    def register(self, plugin, label):
        self.plugin = plugin
        self.label = label
        instance = self()
        return idaapi.register_action(idaapi.action_desc_t(self.get_name(),instance.get_label(),instance))

    @classmethod
    def unregister(self):
        idaapi.unregister_action(self.get_name())


    def activate(self,ctx):
        pass


    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class StackViewer_Menu(MenuContext):
    @classmethod
    def activate(self,ctx):
        k = StackViewer()
        k.Show("Stack Viewer")


class VariableViewer_Menu(MenuContext):
    @classmethod
    def activate(self,ctx):
        k = VariableViewer()
        k.Show("Variable Viewer")







    














class StackInfo(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP  
    comment = ""           
    help = ""                 
    wanted_name = "StackInfo"         
    wanted_hotkey = "" 



    def __init__(self):
        pass



    def init(self):
        

        # 注册菜单
        StackViewer_Menu.register(self, "Open Stack View")
        VariableViewer_Menu.register(self, "Open Variable View")

        # 注册菜单项到IDA的调试窗口中
        idaapi.attach_action_to_menu("Debugger/Debugger windows/Stack Viewer", StackViewer_Menu.get_name(), idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu("Debugger/Debugger windows/Variable Viewer", VariableViewer_Menu.get_name(), idaapi.SETMENU_APP)
        
        # except:
        #     pass
        return idaapi.PLUGIN_OK

    def run(self,arg):
        # k = StackViewer()
        # k.Show(WIDGET_TITLE)

        t = VariableViewer()
        t.Show(WIDGET_TITLE)

        pass




    def term(self):


        
        pass




def PLUGIN_ENTRY():
    return StackInfo()


# idaapi.load_plugin("F:\\Projects\\IDA-StackAnnotation\\IDA-StackExpain.py")