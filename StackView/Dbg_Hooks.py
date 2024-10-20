import idaapi
import idc
import ida_idaapi





class SecDebugHooks(idaapi.DBG_Hooks):
    def __init__(self):
        super(SecDebugHooks, self).__init__()



    def dbg_suspend_process(self,*args):
        print(*args)









