import idaapi


from PyQt5 import QtGui, QtCore, QtWidgets
from PyQt5.QtCore import Qt

#@#
import sys
sys.path.append("F:\\Projects\\IDA-StackAnnotation")
#@#

from StackView.Defines import *
from StackView.Viewer import *
from StackView.Dbg_Hooks import *


class Sec_MenuContext(idaapi.action_handler_t):

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


class SecStackMenu(Sec_MenuContext):
    @classmethod
    def activate(self,ctx):
        k = Sec_Viewer()
        k.Show(WIDGET_TITLE)





    














class StackInfo(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP  
    comment = ""           
    help = ""                 
    wanted_name = "StackInfo"         
    wanted_hotkey = "" 



    def __init__(self):
        pass



    def init(self):
        
        try:
            # 注册函数Hook
            register_dbg_hook()

            # 注册菜单
            SecStackMenu.register(self, "Open Stack View")

            # 注册菜单项到IDA的调试窗口中
            idaapi.attach_action_to_menu("Debugger/Debugger windows/StackMenu", SecStackMenu.get_name(), idaapi.SETMENU_APP)
            
        except:
            pass
        return idaapi.PLUGIN_OK

    def run(self,arg):
        k = Sec_Viewer()
        k.Show(WIDGET_TITLE)
        pass




    def term(self):


        
        pass




def PLUGIN_ENTRY():
    return StackInfo()


# idaapi.load_plugin("F:\\Projects\\IDA-StackAnnotation\\IDA-StackExpain.py")