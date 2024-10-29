import idaapi

from PyQt5 import QtWidgets,QtGui,Qt,QtCore
from PyQt5.QtCore import Qt

from StackView.Defines import *
from StackView.QtContainers.ReadOnlyLineEdit import ReadOnlyLineEdit
from StackView.QtContainers.ReadOnlyTextEdit import ReadOnlyTextEdit




class TemporaryTextEdit(QtWidgets.QTextEdit):
    def __init__(self, text=None, parent=None,bgcolor=None,linecolor=None):
        super(TemporaryTextEdit, self).__init__(text,parent)
        self.table_parent = parent
        self.setGeometry(300, 300, 400, 200)
        self.setReadOnly(True)
        self.setFont(QtGui.QFont(TEXT_FONT, TEXT_FONT_SIZE))
        self.setStyleSheet(f"""selection-color:{TEXT_SELECTED_COLOR};
                                    selection-background-color:{TEXT_SELECTED_BACKGROUND_COLOR};
                                    border: none;background-color: {bgcolor};color: {linecolor}""")
    

    def mouseDoubleClickEvent(self, event):
        super().mouseDoubleClickEvent(event)
        cursor = self.textCursor()
        if (cursor.hasSelection() and hasattr(self.table_parent,"WidgeDoubleClick")):
            selected_text = cursor.selectedText()
            self.table_parent.WidgeDoubleClick(selected_text)

    def contextMenuEvent(self, event):
        pass

    # 保持箭头光标样式
    def enterEvent(self, event):
        self.viewport().setCursor(QtCore.Qt.ArrowCursor) 
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.viewport().setCursor(QtCore.Qt.ArrowCursor) 
        super().leaveEvent(event)




class TemporaryItemViewer(QtWidgets.QMainWindow):
    def __init__(self, parent, item):
        super().__init__(parent)
        self.setWindowTitle(item.objectName())
        self.setGeometry(300, 300, 400, 200)

        # 创建一个中心部件并设置布局
        central_widget = QtWidgets.QWidget(self)
        layout = QtWidgets.QVBoxLayout(central_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(item)

        # 设置中心部件
        self.setCentralWidget(central_widget)


class StackContainer(QtWidgets.QWidget):
    def __init__(self,parent,bitness=64,parent_viewer = None):
        super(StackContainer,self).__init__(parent)

        # 初始化
        self.parent_viewer = parent_viewer
        self.bitness = bitness

        # 设置默认值
        # 由于栈的每个地址都是唯一的，本控件也将地址作为指示每个行的唯一ID
        self.backgroundColor = DEFINE_BACKGROUND_COLOR 
        self.cursor_position = 0   # 指针位置
        self.address_id = []   # 行 -> 地址 
        self.widget_dict = {}   # 控件名 -> 控件
        self.highlighting = []   # 当前高亮的控件
        self.waittorefresh = []   # 需要更新的组件
        self.highlightingAddress = -1   # 当前高亮的行
        self.originalhighlightingAddressColor = []   # 高亮行恢复的颜色
        self.tmp_widget_dict = {}  # 临时的 控件名 -> 控件 用于重置地址

        # 设置窗口大小
        self.setGeometry(400, 400, 800, 600)
        


        # 创建一个 QTableWidget 控件
        self.table_widget = QtWidgets.QTableWidget()

        # 设置表格的行数和列数
        # Format: [Pointer | Address | Value | Type | State | Description]
        headers = ["", "Address", "Value","Description", "Remark", "Type", "State"]
        self.table_widget.setColumnCount(len(headers))
        self.objname_header_dict = {
            0  : "pointer_%X",
            1  : "address_%X",
            2  : "value_%X",
            3  : "description_%X",
            4  : "remark_%X",
            5  : "state_%X",
            6  : "type_%X",
        }
        self.table_widget.setHorizontalHeaderLabels(headers)

        # 设置表格的列表头 高度和宽度
        horizontalHeader = self.table_widget.horizontalHeader()
        horizontalHeader.setSectionsClickable(False)  # 不可选中
        horizontalHeader.setSectionsMovable(True) # 允许移动
        horizontalHeader.setMaximumHeight(33) # 高度
        horizontalHeader.setMinimumSectionSize(50)

        # Pointer Header
        horizontalHeader.resizeSection(0,75)
        horizontalHeader.setSectionResizeMode(0,QtWidgets.QHeaderView.Fixed) 

        # Address Header
        horizontalHeader.resizeSection(1,bitness*4-bitness//2+5)
        horizontalHeader.setSectionResizeMode(1,QtWidgets.QHeaderView.Fixed) 

        # Value Header
        horizontalHeader.resizeSection(2,bitness*4-bitness//2+5)
        horizontalHeader.setSectionResizeMode(2,QtWidgets.QHeaderView.Fixed) 

        # Description Header
        horizontalHeader.resizeSection(3,1000)

        horizontalHeader.resizeSection(4,600)
        horizontalHeader.resizeSection(5,60)
        horizontalHeader.setSectionResizeMode(5,QtWidgets.QHeaderView.Fixed) 
        horizontalHeader.resizeSection(6, 60)
        horizontalHeader.setSectionResizeMode(6,QtWidgets.QHeaderView.Interactive) 


        # 设置行表头高度并隐藏列表头
        verticalheader = self.table_widget.verticalHeader()
        verticalheader.setMaximumSectionSize(27)  
        verticalheader.setMinimumSectionSize(27)  
        verticalheader.setDefaultSectionSize(27)  
        verticalheader.setVisible(False)

        # 右键菜单
        horizontalHeader.setContextMenuPolicy(Qt.CustomContextMenu)
        horizontalHeader.customContextMenuRequested.connect(self.show_column_menu)


        # 设置滚动方式
        self.table_widget.setHorizontalScrollMode(QtWidgets.QTableWidget.ScrollPerPixel)
        self.table_widget.setVerticalScrollMode(QtWidgets.QTableWidget.ScrollPerPixel)
    
        # 设置选中事件：高亮选中的item   高亮选中的行
        self.table_widget.itemSelectionChanged.connect(self.highlight_matching_items)
        self.table_widget.itemSelectionChanged.connect(self.highlight_selected_line)

        # 设置样式
        palette = self.table_widget.palette()
        palette.setColor(QtGui.QPalette.Window, QtGui.QColor(255, 255, 255))
        self.table_widget.setPalette(palette)
        self.reset_QSS()
        self.table_widget.setShowGrid(False)

        # 创建一个垂直布局
        self.hbox = QtWidgets.QVBoxLayout()
        self.hbox.setContentsMargins(0, 0, 0, 0)

        # 将表格添加到布局中
        self.hbox.addWidget(self.table_widget)
        self.setLayout(self.hbox)

        
    def reset_QSS(self):
        QSS_STR = f"""
            QTableWidget {{
                border: none;  /* 移除表格的外部边框 */
                gridline-color: transparent;  /* 移除单元格之间的网格线 */
                background-color: {self.backgroundColor}; 
            }}
            QHeaderView::section {{    /* 表头元素 */
                background-color: {QHEADER_BACKGROUND_COLOR};             
                margin:1px;
            }}                    
            QHeaderView::section:hover{{   /* 指针悬停表头元素 */
                background-color: {QHEADER_BACKGROUND_COLOR_HOVER}; 
                font-weight: blod;
                border: none;  /* 移除表格的外部边框 */
                
            }}
            QHeaderView::section:checked{{   /* 选中表头元素 */
                margin:0px;
                font-style: normal;
                font-weight: normal;
            }}
                                

            QTableWidget::item:selected{{   /* 选中条目元素 */
                background-color: {SELECT_LINE_BACKGROUND_COLOR};
                border: none;  /* 移除表格的外部边框 */
            }}
        """
        self.table_widget.setStyleSheet(QSS_STR)
    


    # 设置表头右键菜单：调整列可见性
    def show_column_menu(self, position):
        menu = QtWidgets.QMenu(self)
        
        for col in range(3,self.table_widget.columnCount()):
            action = QtWidgets.QAction(self.table_widget.horizontalHeaderItem(col).text(), self)
            action.setCheckable(True)
            action.setChecked(not self.table_widget.isColumnHidden(col))
            action.triggered.connect(lambda checked, c=col: self.toggle_column_visibility(c))
            menu.addAction(action)
        
        menu.exec_(self.table_widget.horizontalHeader().mapToGlobal(position))

    def toggle_column_visibility(self, column):
        if self.table_widget.isColumnHidden(column):
            self.table_widget.showColumn(column)
        else:
            self.table_widget.hideColumn(column)




    # 在控件显示时刷新
    def showEvent(self, event):
        self.parent_viewer.RefreshStackContainer()
        super().showEvent(event) 

    # 显示右键菜单
    def contextMenuEvent(self, event):
        self.show_context_menu(self.mapToGlobal(event.pos()))


    def show_context_menu(self, pos, item = None):
        # 创建上下文菜单
        menu = QtWidgets.QMenu(self)

        # 添加菜单项
        action1 = QtWidgets.QAction('Refresh Window', self)
        action2 = QtWidgets.QAction('Reinitialize the window', self)
        action3 = QtWidgets.QAction('Show The Item', self)

        # 连接菜单项的触发事件
        action1.triggered.connect(self.RefreshWindow)
        action2.triggered.connect(self.ReinitializeWindows)
        action3.triggered.connect(lambda: self.ShowTheItem(item))

        if(item == None):
            action3.setEnabled(False)

        # 添加菜单项到菜单
        menu.addAction(action1)
        menu.addAction(action2)
        menu.addSeparator()
        menu.addAction(action3)

        # 显示菜单
        menu.exec_(pos)

    # 刷新窗口
    def RefreshWindow(self):
        horizontalHeader = self.table_widget.horizontalHeader()
        horizontalHeader.resizeSection(0,76)
        horizontalHeader.resizeSection(0,75)
        
        for edit in self.waittorefresh:
            edit.Refresh()
        self.waittorefresh.clear()

    # 重新初始化窗口
    def ReinitializeWindows(self):
        self.parent_viewer.InitStackContainer()


    def ShowTheItem(self,item):
        tmp_text_edit = TemporaryTextEdit(None,self,self.backgroundColor,item.linecolor)
        if(isinstance(item,ReadOnlyTextEdit)):
            text = item.toHtml()
            tmp_text_edit.setHtml(text)

        elif(isinstance(item,ReadOnlyLineEdit)):
            text = item.text()
            tmp_text_edit.setPlainText(text)

        itemviewer = TemporaryItemViewer(self,tmp_text_edit)
        itemviewer.show()  
        



    def highlight_matching_items(self):
        # 恢复默认背景颜色
        if(self.highlighting != []):
            for items in self.highlighting:
                if(items[0] in self.widget_dict):
                    item = self.widget_dict[items[0]]
                    item.SetbgColor(items[1])
                    self.waittorefresh.append(item)
            self.highlighting.clear()

        # 获取当前选中的单元格
        selected_items = [self.table_widget.cellWidget(self.table_widget.currentRow(),self.table_widget.currentColumn())]
        if not selected_items:
            return False
        
        # 高亮所有值相同的单元格
        if(selected_items[0] != None):
            selected_value = selected_items[0].GetLine()
            if(selected_value != ""):
                for item in self.widget_dict:
                    if(self.widget_dict[item].GetLine() == selected_value and isinstance(self.widget_dict[item],ReadOnlyLineEdit) ):
                        originalcolor = self.widget_dict[item].GetbgColor()
                        self.widget_dict[item].SetbgColor(0xFFFF33)
                        self.highlighting.append([item,originalcolor])
                        self.waittorefresh.append(self.widget_dict[item])

        self.RefreshWindow()
        return True

    # 改变一整行的颜色， colors接收单个对象或数组
    def change_line_color(self,line,colors):
        if(line >= 0):
            for i in range(self.table_widget.columnCount()):
                if(isinstance(colors,list)):
                    color = colors[i]
                else:
                    color = colors

                if(isinstance(color,str)):
                    item = self.table_widget.item(line,i)
                    item.setBackground(QtGui.QColor(color)) 
                elif(isinstance(color, QtGui.QBrush) or isinstance(color, QtGui.QColor)):
                    item = self.table_widget.item(line,i)
                    item.setBackground(color)

    def highlight_selected_line(self):
        if(self.highlightingAddress >= 0 and self.highlightingAddress in self.address_id):
            self.change_line_color(self.address_id.index(self.highlightingAddress), self.originalhighlightingAddressColor)
            self.originalhighlightingAddressColor.clear()

        select_line = self.table_widget.currentRow()
        self.highlightingAddress = self.address_id[select_line]

        for i in range(self.table_widget.columnCount()):
            item = self.table_widget.item(select_line,i)
            if(item):
                brush = item.background().color()
            else:
                brush = TRANSPARENT
            self.originalhighlightingAddressColor.append(brush)
        self.change_line_color(self.address_id.index(self.highlightingAddress), SELECT_LINE_BACKGROUND_COLOR)
        
    def get_visible_top_row(self):
            viewport = self.table_widget.viewport()
            top_y = viewport.rect().top()
            top_row = self.table_widget.verticalHeader().visualIndexAt(top_y)
            return top_row

    def scrollrow(self,num):
        current_row = self.get_visible_top_row()
        target_row = current_row + num
        self.table_widget.scrollToItem(self.table_widget.item(target_row, 0),self.table_widget.PositionAtTop)

    def edit_wedge(self,key = None, text = None,color = None):
        if(key in self.widget_dict):
            item = self.widget_dict[key]
            item.EditLine(text,color)
            self.waittorefresh.append(item)
            return True
        return False
    
    def insert_wedge(self,key = None, text = None,color = None):
        if(key in self.widget_dict):
            item = self.widget_dict[key]
            item.InsertText(text,color)
            self.waittorefresh.append(item)
            return True
        return False

    def get_wedge_text(self,key = None):
        if(key in self.widget_dict):
            item = self.widget_dict[key]
            return item.GetLine()
        return False

    def setcolor_wedge(self,key = None, color = None):
        if(key in self.widget_dict):
            item = self.widget_dict[key]
            item.SetColor(color)
            self.waittorefresh.append(item)
            return True
        return False

    def setbgcolor_wedge(self,key = None, color = None):
        if(key in self.widget_dict):
            item = self.widget_dict[key]
            item.SetbgColor(color)
            self.waittorefresh.append(item)
            return True
        return False

    def clear_wedge(self,key = None):
        if(key in self.widget_dict):
            item = self.widget_dict[key]
            item.Clear()
            self.waittorefresh.append(item)
            return True
        return False



    def AddLine(self,row,Address, Value, Meaning = None, Type = None, State = None, Description = None):
        if(Address in self.address_id):
            return False
        
        self.address_id.insert(row, Address)

        # 插入新行
        self.table_widget.insertRow(row)

        unit_size = self.bitness // 8

        if(unit_size == 8):
            address_str =  "%016X"%Address
            value_str = "%016X"%Value
        elif(unit_size == 4):
            address_str =  "%08X"%Address
            value_str = "%08X"%Value
        elif(unit_size == 2):
            address_str =  "%04X"%Address
            value_str = "%04X"%Value


        # 创建 ReadOnlyLineEdit 小部件并设置文本
        pointer_widget = ReadOnlyLineEdit("", self)
        address_widget = ReadOnlyLineEdit(address_str, self)

        value_widget = ReadOnlyLineEdit(value_str, self)
        description_widget = ReadOnlyTextEdit(Meaning, self)
        remark_widget = ReadOnlyLineEdit(Description, self)
        type_widget = ReadOnlyLineEdit(Type, self)
        state_widget = ReadOnlyLineEdit(State, self)

        pointer_widget.setObjectName("pointer_%X"%Address)
        address_widget.setObjectName("address_%X"%Address)
        value_widget.setObjectName("value_%X"%Address)
        description_widget.setObjectName("description_%X"%Address)
        remark_widget.setObjectName("remark_%X"%Address)
        type_widget.setObjectName("type_%X"%Address)
        state_widget.setObjectName("state_%X"%Address)

        # 将小部件添加到表格中
        self.table_widget.setCellWidget(row, 0, pointer_widget)
        self.table_widget.setCellWidget(row, 1, address_widget)
        self.table_widget.setCellWidget(row, 2, value_widget)
        self.table_widget.setCellWidget(row, 3, description_widget)
        self.table_widget.setCellWidget(row, 4, remark_widget)
        self.table_widget.setCellWidget(row, 5, state_widget)
        self.table_widget.setCellWidget(row, 6, type_widget)
        for i in range(0,self.table_widget.columnCount()):
            item = self.table_widget.cellWidget(row,i)
            if item != None:
                self.widget_dict[item.objectName()] = item
                self.waittorefresh.append(item)

            # 为不同列设置颜色
            tableItem = QtWidgets.QTableWidgetItem()
            if(i % 2):
                tableItem.setBackground(QtGui.QColor(DEBUG_BACKGROUND_ROW_COLOR1))
            else:
                tableItem.setBackground(QtGui.QColor(DEBUG_BACKGROUND_ROW_COLOR2))
            self.table_widget.setItem(row, i, tableItem)
        return True

    # 删除指定行
    def DeleteLine(self, Address):
            if Address not in self.address_id:
                return False
            # 找到对应地址的行索引
            row_index = self.address_id.index(Address)

            # 从 table_widget 中删除该行
            self.table_widget.removeRow(row_index)

            # 从 address_id 中删除该地址
            self.address_id.remove(Address)

            # 从 widget_dict 中删除相关的小部件
            keys_to_remove = [i%(Address) for i in self.objname_header_dict.values()]
            for key in keys_to_remove:
                if key in self.widget_dict:
                    del self.widget_dict[key]

            return True




    ''' *args: Value, Type = None, State = None, Description = None '''
    def addLineAtBegin(self,Address = None,*args):
        if(len(self.address_id) == 0 and Address == None):
            idaapi.error("Error, Please reinitialize the window")
            return False
        elif(len(self.address_id) != 0):
            target_addr = self.address_id[0] - self.bitness // 8
        else:
            target_addr = Address

        self.scrollrow(1)
        return self.AddLine(0,target_addr, *args)


    def delLineAtBegin(self):
        if self.table_widget.rowCount() > 0:
            Address = self.address_id[0]
            self.scrollrow(-1)
            return self.DeleteLine(Address)
        else:
            return False

    def addLineAtEnd(self,Address = None,*args):
        if(len(self.address_id) == 0 and Address == None):
            idaapi.error("Error, Please reinitialize the window")
            return False
        elif(len(self.address_id) != 0):
            target_addr = self.address_id[self.table_widget.rowCount()-1] + self.bitness // 8
        elif(Address != None):
            target_addr = Address
        return self.AddLine(self.table_widget.rowCount(),target_addr, *args)

    def delLineAtEnd(self):
        if self.table_widget.rowCount() > 0:
            Address = self.address_id[self.table_widget.rowCount()-1]
            self.DeleteLine(Address)
            return True
        else:
            return False

    def EditItem(self,Address,Header,text,color = DEFINE_LINE_COLOR):
        key = self.objname_header_dict[Header]%Address
        if(key != None):
            if(Header == 2):
                unit_size = self.bitness // 8

                if(unit_size == 8):
                    text =  "%016X"%text
                elif(unit_size == 4):
                    text =  "%08X"%text
                elif(unit_size == 2):
                    text =  "%04X"%text
                return self.edit_wedge(key,text,color)

            else:
                return self.edit_wedge(key,text,color)
        return False

    def InsertText(self,Address,Header,text,color = DEFINE_LINE_COLOR):
        key = self.objname_header_dict[Header]%Address
        if(key != None):
            if(Header == 2):
                unit_size = self.bitness // 8

                if(unit_size == 8):
                    text =  "%016X"%text
                elif(unit_size == 4):
                    text =  "%08X"%text
                elif(unit_size == 2):
                    text =  "%04X"%text
                return self.insert_wedge(key,text,color)

            else:
                return self.insert_wedge(key,text,color)
        return False

    def GetItemText(self,Address,Header):
        key = self.objname_header_dict[Header]%Address
        if(key != None):
            return self.get_wedge_text(key)
        return False
    

    def ChangeEditColor(self,Address,Header,Color):
        key = self.objname_header_dict[Header]%Address
        if(key != None):
            return self.setcolor_wedge(key,Color)
        return False


    def ChangeEditbgColor(self,Address,Header,Color):

        key = self.objname_header_dict[Header]%Address
        if(key != None):
            return self.setbgcolor_wedge(key,Color)
        return False

    def ChangeLinebgColor(self,Address,Color):
        if Address not in self.address_id:
            # print("[ChangeLinebgColor] Address not found")
            return False
        # 找到对应地址的行索引
        row_index = self.address_id.index(Address)
        self.change_line_color(row_index,Color)


    def ClearItem(self,Address,Header):
        key = self.objname_header_dict[Header]%Address
        if(key != None):
            return self.clear_wedge(key)
        return False

    def ClearAllLines(self):
        self.table_widget.setRowCount(0)
        self.address_id.clear()
        self.widget_dict.clear()
        self.waittorefresh.clear()
        self.highlighting.clear()
        self.highlightingAddress = -1

    def RolltoAddress(self,Address):
        if Address not in self.address_id:
                return False
        # 找到对应地址的行索引
        row_index = self.address_id.index(Address)
        self.table_widget.scrollToItem(self.table_widget.item(row_index, 0),self.table_widget.PositionAtTop)



    def GetAddressRange(self):
        if(self.address_id != []):
            return self.address_id[0], self.address_id[len(self.address_id)-1]
        else:
            return None, None
        
    def EnableUpdates(self):
        self.table_widget.setUpdatesEnabled(True)

    def DisableUpdates(self):
        self.table_widget.setUpdatesEnabled(False)


    def WidgeDoubleClick(self,selected_data): 
        if(hasattr(self.parent_viewer,"WidgeDoubleClick")):
            self.parent_viewer.WidgeDoubleClick(selected_data)

    # 重设行地址
    def ResetLine(self,row,Address):
        if row < 0 or row >= self.table_widget.rowCount():
            return False
            
        for i in range(0,self.table_widget.columnCount()):
            item = self.table_widget.cellWidget(row,i)

            if item != None:
                new_objname = (self.objname_header_dict[i])%Address

                self.tmp_widget_dict[new_objname] = self.widget_dict[item.objectName()]

                item.setObjectName(new_objname)
                item.Clear()
                self.waittorefresh.append(item)
                if(i == 1):
                    unit_size = self.bitness // 8
                    if(unit_size == 8):
                        address_str =  "%016X"%Address
                    elif(unit_size == 4):
                        address_str =  "%08X"%Address
                    elif(unit_size == 2):
                        address_str =  "%04X"%Address
                    item.setText(address_str)
        return True

    # 重设整个窗口的地址
    def ResetAddress(self,Address):



        start_address =  Address - STACK_SIZE_ABOVE * self.bitness // 8
        self.tmp_widget_dict.clear()
        self.address_id.clear()

        for i in range(self.table_widget.rowCount()):
            self.ResetLine(i, start_address + i * self.bitness // 8)
            self.address_id.append(start_address + i * self.bitness // 8)
        self.widget_dict =  dict(self.tmp_widget_dict)


        self.waittorefresh.clear()
        self.highlighting.clear()
        self.highlightingAddress = -1