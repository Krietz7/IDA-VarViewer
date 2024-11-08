from idaapi import DBG_Hooks,refresh_debugger_memory

class DebugHooks(DBG_Hooks):
    def __init__(self,callback):
        super().__init__()
        self.callback = None
        if callback is not None:
            self.callback = callback

    def dbg_suspend_process(self,*args):
        refresh_debugger_memory()
        if self.callback is not None:
            self.callback(0)
