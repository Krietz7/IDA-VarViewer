import idaapi

from PyQt5 import QtWidgets,QtGui,Qt 
from PyQt5.QtCore import Qt



from StackView.Defines import *



class ReadOnlyLineEdit(QtWidgets.QLineEdit):
    def __init__(self,text=None,parent=None):
        super(ReadOnlyLineEdit, self).__init__(text,parent)
        self.table_parent = parent
        self.setReadOnly(True)
        self.setFont(QtGui.QFont(TEXT_FONT, TEXT_FONT_SIZE))


        self.linecolor = DEFINE_LINE_COLOR
        self.linebgcolor = TRANSPARENT

        self._cursor_visible = True
        self.cursor_timer = None

        self.cursorPositionChanged.connect(self.cursorPositionChange)
        self.adjust_line_edit_width()
        self.setStyle()

    def focusInEvent(self, event):
        super(ReadOnlyLineEdit, self).focusInEvent(event)
        self.cursorPositionChange()
        if(self.table_parent):
            self.setCursorPosition(self.table_parent.cursor_position)
        
        if not self.cursor_timer:
            self.cursor_timer = self.startTimer(500) 

    def focusOutEvent(self, event):
        super(ReadOnlyLineEdit, self).focusOutEvent(event)
        if(self.table_parent):
            self.table_parent.cursor_position = self.cursorPosition()
        if self.cursor_timer is not None:
            self.killTimer(self.cursor_timer)
            self.cursor_timer = None
        self._cursor_visible = False
        self.update()

    def cursorPositionChange(self,event = None):
        if self.cursor_timer is not None:
            self.killTimer(self.cursor_timer)
        self._cursor_visible = True
        self.cursor_timer = self.startTimer(500)

    def timerEvent(self, event):
        if self.cursor_timer == event.timerId():
            self._cursor_visible = not self._cursor_visible
            self.update()
        super(ReadOnlyLineEdit, self).timerEvent(event)

    def paintEvent(self, event):
        super(ReadOnlyLineEdit, self).paintEvent(event)
        text = self.text()
        if self.isReadOnly() and self.hasFocus() and self._cursor_visible and text != '':
            painter = QtGui.QPainter(self)
            cursor_pos = self.cursorRect().left()
            cursor_height = self.cursorRect().height()
            painter.fillRect(cursor_pos+4, 0, 2, cursor_height+10,QtGui.QColor('black'))

    def contextMenuEvent(self, event):
        # 将局部坐标转换为全局坐标
        global_pos = self.mapToGlobal(event.pos())
        # 调用表格的右键菜单显示方法
        if(self.table_parent):
            self.table_parent.show_context_menu(global_pos)

    # 更新文本框宽度
    def adjust_line_edit_width(self):
        # 获取当前字体
        font = self.font()
        # 创建 QFontMetrics 对象
        font_metrics = QtGui.QFontMetrics(font)
        text = self.text()
        text_width = font_metrics.width(text)
        extra_padding =  5
        total_width = text_width + extra_padding

        # 设置 QLineEdit 的固定宽度
        self.setFixedWidth(total_width)

    # 设置样式
    def setStyle(self):
        super(ReadOnlyLineEdit, self).setStyleSheet(f"border: none;background-color: {self.linebgcolor};color: {self.linecolor}")



    def EditLine(self, text):
        self.blockSignals(True)
        self.setText(text)
        self.blockSignals(False)
        self.adjust_line_edit_width()

    def SetColor(self, color):
        if(isinstance(color,str)):
            self.linecolor = color
        elif(isinstance(color,int)):
            self.linecolor = "#" + "%06X"%color
        self.setStyle()


    def SetbgColor(self, color):
        if(isinstance(color,str)):
            self.linebgcolor = color
        elif(isinstance(color,int)):
            self.linebgcolor = "#" + "%06X"%color
        self.setStyle()      

    def GetbgColor(self):
        return self.linebgcolor




class StackContainer(QtWidgets.QWidget):
    def __init__(self, parent=None,bitness=64):
        super(StackContainer,self).__init__()
        self.bitness = bitness

        self.cursor_position = 0
        self.address_id = []
        self.widget_dict = {}
        self.highlighting = []
        self.highlightingAddress = -1
        self.backgroundColor = DEFINE_BACKGROUND_COLOR
        self.originalhighlightingAddressColor = TRANSPARENT

        # 设置窗口大小
        self.setGeometry(400, 400, 800, 600)
        

        # 创建一个 QTableWidget 控件
        self.table_widget = QtWidgets.QTableWidget()

        # 设置表格的行数和列数
        

        # Format: [Pointer | Address | Value | Type | State | Description]
        headers = ["", "Address", "Value", "Type", "State", "Description"]
        self.table_widget.setColumnCount(len(headers))
        self.objname_header_dict = {
            1   : "pointer_%X",
            2  : "address_%X",
            3   : "value_%X",
            4  : "type_%X",
            5  : "state_%X",
            6  : "description_%X",
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

        # Address Header
        horizontalHeader.resizeSection(1,bitness*4-bitness//2+5)
        horizontalHeader.setSectionResizeMode(1,QtWidgets.QHeaderView.Fixed) 

        # Value Header
        horizontalHeader.resizeSection(2,bitness*4-bitness//2+5)
        horizontalHeader.setSectionResizeMode(2,QtWidgets.QHeaderView.Fixed) 



        horizontalHeader.resizeSection(3,55)
        horizontalHeader.resizeSection(4,60)


        # Description Header
        horizontalHeader.resizeSection(5, 300)
        horizontalHeader.setSectionResizeMode(5,QtWidgets.QHeaderView.Stretch) 



        # 设置行表头高度并隐藏列表头
        verticalheader = self.table_widget.verticalHeader()
        verticalheader.setMinimumSectionSize(27)  
        verticalheader.setDefaultSectionSize(27)  
        verticalheader.setVisible(False)

        # 右键菜单
        horizontalHeader.setContextMenuPolicy(Qt.CustomContextMenu)
        horizontalHeader.customContextMenuRequested.connect(self.show_column_menu)


        # 设置滚动方式
        self.table_widget.setHorizontalScrollMode(QtWidgets.QTableWidget.ScrollPerPixel)
        self.table_widget.setVerticalScrollMode(QtWidgets.QTableWidget.ScrollPerPixel)
    
        self.reset_QSS()


        palette = self.table_widget.palette()
        palette.setColor(QtGui.QPalette.Window, QtGui.QColor(255, 255, 255))
        self.table_widget.setPalette(palette)

        self.table_widget.itemSelectionChanged.connect(self.highlight_matching_items)
        self.table_widget.itemSelectionChanged.connect(self.highlight_selected_line)


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
                border: none;  /* 移除表格的外部边框 */
                margin:0px;
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
        self.table_widget.setShowGrid(False)
    



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





    def contextMenuEvent(self, event):
        self.show_context_menu(self.mapToGlobal(event.pos()))


    def show_context_menu(self, pos):
        # 创建上下文菜单
        menu = QtWidgets.QMenu(self)

        # 添加菜单项
        action1 = QtWidgets.QAction('Action 1', self)
        action2 = QtWidgets.QAction('Action 2', self)
        action3 = QtWidgets.QAction('Action 3', self)

        # 连接菜单项的触发事件
        action1.triggered.connect(self.on_action1_triggered)
        action2.triggered.connect(self.on_action2_triggered)
        action3.triggered.connect(self.on_action3_triggered)

        # 添加菜单项到菜单
        menu.addAction(action1)
        menu.addAction(action2)
        menu.addAction(action3)

        # 显示菜单
        menu.exec_(pos)


    def on_action1_triggered(self):
        print("Action 1 triggered")

    def on_action2_triggered(self):
        print("Action 2 triggered")

    def on_action3_triggered(self):
        print("Action 3 triggered")

    def highlight_matching_items(self):
        # 恢复默认背景颜色
        if(self.highlighting != []):
            for items in self.highlighting:
                item = self.widget_dict[items[0]]
                item.SetbgColor(items[1])
            self.highlighting = []
        
        # 获取当前选中的单元格
        #获取当前选中的列
        #获取当前选中的行
        selected_items = [self.table_widget.cellWidget(self.table_widget.currentRow(),self.table_widget.currentColumn())]
        if not selected_items:
            return False
        
        selected_value = selected_items[0].text()
        
        # # 高亮所有值相同的单元格
        if(selected_value != ""):
            for item in self.widget_dict:
                if(self.widget_dict[item].text() == selected_value):
                    originalcolor = self.widget_dict[item].GetbgColor()
                    self.widget_dict[item].SetbgColor(0xFFFF33)
                    self.highlighting.append([item,originalcolor])
        return True


    def change_line_color(self,line,color):
        if(line >= 0):
            if(isinstance(color,str)):
                for i in range(self.table_widget.columnCount()):
                    item = self.table_widget.item(line,i)
                    item.setBackground(QtGui.QColor(color)) 
            elif(isinstance(color, QtGui.QBrush) or isinstance(color, QtGui.QColor)):
                for i in range(self.table_widget.columnCount()):
                    item = self.table_widget.item(line,i)
                    item.setBackground(color)




    def highlight_selected_line(self):
        if(self.highlightingAddress >= 0):
            self.change_line_color(self.address_id.index(self.highlightingAddress), self.originalhighlightingAddressColor)


        select_line = self.table_widget.currentRow()
        self.highlightingAddress = self.address_id[select_line]
        item = self.table_widget.item(select_line,1)
        if(item):
            brush = item.background()
        else:
            brush = TRANSPARENT
        self.originalhighlightingAddressColor = brush
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






    def edit_wedge(self,key = None, text = None):
        if(key in self.widget_dict):
            item = self.widget_dict[key]
            item.EditLine(text)
            return True
        return False

    def setcolor_wedge(self,key = None, color = None):
        if(key in self.widget_dict):
            item = self.widget_dict[key]
            item.SetColor(color)
            return True
        return False

    def setbgcolor_wedge(self,key = None, color = None):
        if(key in self.widget_dict):
            item = self.widget_dict[key]
            item.SetbgColor(color)
            return True
        return False

    def AddLine(self,row,Address, Value, Type = None, State = None, Description = None):
        if(Address in self.address_id):
            print("Existing address")
            return False
        self.address_id.insert(row, Address)


        # 插入新行
        self.table_widget.insertRow(row)

        unit_size = self.bitness / 8

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
        type_widget = ReadOnlyLineEdit(Type, self)
        state_widget = ReadOnlyLineEdit(State, self)
        description_widget = ReadOnlyLineEdit(Description, self)

        pointer_widget.setObjectName("pointer_%X"%Address)
        address_widget.setObjectName("address_%X"%Address)
        value_widget.setObjectName("value_%X"%Address)
        type_widget.setObjectName("type_%X"%Address)
        state_widget.setObjectName("state_%X"%Address)
        description_widget.setObjectName("description_%X"%Address)
        # 将小部件添加到表格中
        
        self.table_widget.setCellWidget(row, 0, pointer_widget)
        self.table_widget.setCellWidget(row, 1, address_widget)
        self.table_widget.setCellWidget(row, 2, value_widget)
        self.table_widget.setCellWidget(row, 3, type_widget)
        self.table_widget.setCellWidget(row, 4, state_widget)
        self.table_widget.setCellWidget(row, 5, description_widget)
        for i in range(0,self.table_widget.columnCount()):
            self.table_widget.setItem(row, i, QtWidgets.QTableWidgetItem())
            item = self.table_widget.cellWidget(row,i)
            if item != None:
                self.widget_dict[item.objectName()] = item
        return True
        






    # 删除指定行
    def DeleteLine(self, Address):

            if Address not in self.address_id:
                print("Address not found")
                return False
            # 找到对应地址的行索引
            row_index = self.address_id.index(Address)

            # 从 table_widget 中删除该行
            self.table_widget.removeRow(row_index)

            # 从 address_id 中删除该地址
            self.address_id.remove(Address)

            # 从 widget_dict 中删除相关的小部件
            keys_to_remove = [
                f"pointer_{Address:X}",
                f"address_{Address:X}",
                f"value_{Address:X}",
                f"type_{Address:X}",
                f"state_{Address:X}",
                f"description_{Address:X}"
            ]
            for key in keys_to_remove:
                if key in self.widget_dict:
                    del self.widget_dict[key]


            return True




    ''' *args: Value, Type = None, State = None, Description = None '''
    def addLineAtBegin(self,Address = None,*args):
        if(len(self.address_id) == 0 and Address == None):
            print("Please give a base address")
            return False
        elif(len(self.address_id) != 0):
            target_addr = self.address_id[0] - int(self.bitness / 8)
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
            print("Please give a base address")
            return False
        elif(len(self.address_id) != 0):
            target_addr = self.address_id[self.table_widget.rowCount()-1] + int(self.bitness / 8)
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




    def EditLine(self,Address,Header,text):
        key = self.objname_header_dict[Header]%Address
        if(key != None):
            return self.edit_wedge(key,text)
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
            print("Address not found")
            return False
        # 找到对应地址的行索引
        row_index = self.address_id.index(Address)
        self.change_line_color(row_index,Color)


    def ClearAllLines(self):
        while True:
            if(not self.delLineAtBegin()):
                break


    def RolltoAddress(self,Address):
        if Address not in self.address_id:
                print("Address not found")
                return False
        # 找到对应地址的行索引
        row_index = self.address_id.index(Address)
        self.table_widget.scrollToItem(self.table_widget.item(row_index, 0),self.table_widget.PositionAtTop)