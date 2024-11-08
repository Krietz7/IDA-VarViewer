import idaapi

from VarViewer.config import *
from VarViewer.StackViewer import *
from VarViewer.VariableViewer import *

class MenuContext(idaapi.action_handler_t):
    @classmethod
    def get_name(cls):
        return cls.__name__

    @classmethod
    def get_label(cls):
        return cls.label

    @classmethod
    def register(cls, plugin, label, hotkey):
        cls.plugin = plugin
        cls.label = label
        instance = cls()
        return idaapi.register_action(idaapi.action_desc_t(cls.get_name(),instance.get_label(),instance,hotkey))

    @classmethod
    def unregister(cls):
        idaapi.unregister_action(cls.get_name())

    def activate(self,ctx):
        pass

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class StackViewer_Menu(MenuContext):
    @classmethod
    def activate(cls,ctx):
        k = StackViewer()
        k.Show("Stack Viewer")


class VariableViewer_Menu(MenuContext):
    @classmethod
    def activate(cls,ctx):
        k = VariableViewer()
        k.Show("Variable Viewer")

class StackInfo(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = ""
    help = ""
    wanted_name = "StackInfo"
    wanted_hotkey = STACK_VIEW_HOTKEY

    def __init__(self):
        pass

    def init(self):
        StackViewer_Menu.register(self, "Open Stack View",STACK_VIEW_HOTKEY)
        VariableViewer_Menu.register(self, "Open Variable View",VARIABLE_VIEW_HOTKEY)

        idaapi.attach_action_to_menu("Debugger/Debugger windows/Stack Viewer", StackViewer_Menu.get_name(), idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu("Debugger/Debugger windows/Variable Viewer", VariableViewer_Menu.get_name(), idaapi.SETMENU_APP)

        return idaapi.PLUGIN_OK

    def run(self,arg):
        k = StackViewer()
        k.Show(WIDGET_TITLE)

    def term(self):
        pass

def PLUGIN_ENTRY():
    return StackInfo()
