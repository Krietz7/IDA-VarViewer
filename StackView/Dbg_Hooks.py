import idaapi
import idc
import ida_idaapi





class SecDebugHooks(idaapi.DBG_Hooks):
    def __init__(self,callback):
        super(SecDebugHooks, self).__init__()
        self.callback = callback


    # 进程暂停
    def dbg_suspend_process(self):
        idaapi.refresh_debugger_memory()
        self.callback(0)

    # def dbg_process_attach(self, pid, tid, ea, name, base, size):
    #     idaapi.refresh_debugger_memory()
    #     self.callback(1)




def register_dbg_hook():
    global dbg_hook
    try:
        if dbg_hook:
            dbg_hook.unhook()    # 已注册 析构
    except:
        pass
    dbg_hook = SecDebugHooks()  # 实例化DbgHook()
    dbg_hook.hook()   # hook




