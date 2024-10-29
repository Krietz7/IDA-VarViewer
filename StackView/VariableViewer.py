import idaapi
import idc


from PyQt5 import QtWidgets

import time
import string


from StackView.Defines import *
from StackView.DbgStackInspector import *
from StackView.QtContainers.VariableContainer import *
from StackView.Dbg_Hooks import *
from StackView.FunctionInfo import *


class VariableViewer(idaapi.PluginForm):
    def __init__(self):
        super(VariableViewer, self).__init__()    # 初始化父类
        self.Bitness = SEC_cpu_info.bitness  # 位数
        self.bitnessSize = self.Bitness // 8
        self.endinness = SEC_cpu_info.endinness
        self.base_pointer_name,self.stack_pointer_name,self.two_pointer_name,self.instruction_pointer_name = GetStackRegsName()


        self.func_address_list = {}


    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)  
        self.InitGUI()

    def InitGUI(self):
        self.hbox = QtWidgets.QVBoxLayout()

        self.VariableContainer = VariableContainer(self.parent)

        self.hbox.setContentsMargins(0, 0, 0, 0)
        self.hbox.addWidget(self.VariableContainer)
        # 设置父窗口的布局
        self.parent.setLayout(self.hbox)
        
        if(GetDbgStatus()):
            self.VariableContainer.backgroundcolor = DEBUG_BACKGROUND_COLOR
            self.VariableContainer.reset_QSS()

        self.InitDbgHooks()
        
        if(GetDbgStatus()):
            self.InitVariableContainer()
            self.RefreshVariableContainer()

    def InitDbgHooks(self):
        def callbacks(operation):
            # 调试暂停
            if(operation == 0):
                # 窗口在前台显示
                
                self.RefreshVariableContainer()
                self.VariableContainer.RefreshWindow()




        self.hook = SecDebugHooks(callbacks)
        self.hook.hook()
        pass


    def InitVariableContainer(self):
        # Watching 
        # Current focus in
        # Local variables
        # Global variables

        self.VariableContainer.add_top_level_item("watching","Watching",TOP_ITEM_COLOR)
        self.VariableContainer.add_top_level_item("focusin","Current forus in",TOP_ITEM_COLOR)
        self.VariableContainer.add_top_level_item("lvar","Local variables",TOP_ITEM_COLOR)
        self.VariableContainer.add_top_level_item("gvar","Global variables",TOP_ITEM_COLOR)
        self.VariableContainer.RefreshWindow()





    def RefreshVariableContainer(self):
        self.RefreshLocalvariables()


        self.VariableContainer.RefreshWindow()



    def RefreshLocalvariables(self):
        func_stack_trace = self.GetFunctionStackTrace()
        self.Removefinishfuction(func_stack_trace)
        


        for base_address in func_stack_trace.keys():
            func = func_stack_trace[base_address]
            func_name = ida_funcs.get_func_name(func.start_ea)
            func_id = f"{func_name}_{base_address:X}"

            
            if(base_address not in self.func_address_list and self.VariableContainer.add_func_items( \
                "lvar",func_id,f"{func_name}({base_address:X})",FUNCTION_ITEM_COLOR)):

                self.func_address_list[base_address] = ["lvar",func_id]
                stk_var_list,reg1_var_list,reg2_var_list = GetFuncLocationVarAt(func)

            


    def Removefinishfuction(self,func_stack_trace):
        # 结束函数后，从列表中删除
        for base_address in list(self.func_address_list.keys()):
            if(base_address not in func_stack_trace.keys()):
                t = self.VariableContainer.RemoveFunc(self.func_address_list[base_address][0],self.func_address_list[base_address][1])
                self.func_address_list.pop(base_address)








    # 获取函数调用链上的所有函数基址  返回： 函数基址 结构体 字典
    def GetFunctionStackTrace(self):
        try:
            sp_reg_value = idaapi.get_reg_val(self.stack_pointer_name)
            ip_reg_value = idaapi.get_reg_val(self.instruction_pointer_name)
        except:
            return


        func_stack_trace = {}

        tid = ida_dbg.get_current_thread()
        trace = ida_idd.call_stack_t()
        if (ida_dbg.collect_stack_trace(tid, trace)):
            frame_depth = trace.size()

            stackframe_address = sp_reg_value
            instruction_address = ip_reg_value

            for depth in range(frame_depth - 1):

                func = ida_funcs.get_fchunk(instruction_address)
                func_base_addr = GetFrameBaseAddress(func,instruction_address,stackframe_address,self.Bitness,self.endinness, depth)

                # 根据信息寻找上一层函数的基址

                if(func_base_addr != None):
                    instruction_address = trace[depth+1].callea
                    stackframe_address = func_base_addr + self.bitnessSize
                    func_stack_trace[func_base_addr] = func
                else:
                    break

        return func_stack_trace


    def OnClose(self, form):
        # if self.hook:
        #     self.hook.unhook()
        pass
