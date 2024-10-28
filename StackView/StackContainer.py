import idaapi

from PyQt5 import QtWidgets,QtGui,Qt,QtCore
from PyQt5.QtCore import Qt



from StackView.Defines import *

class ReadOnlyLineEdit(QtWidgets.QLineEdit):
    def __init__(self,text=None,parent=None):
        super(ReadOnlyLineEdit, self).__init__(text,parent)
        if(not isinstance(parent,StackContainer)):
            raise("parent widge class must be StackContainer")
        self.table_parent = parent
        self.setReadOnly(True)
        self.setFont(QtGui.QFont(TEXT_FONT, TEXT_FONT_SIZE))


        self.linecolor = DEFINE_LINE_COLOR
        self.linebgcolor = TRANSPARENT

        self._cursor_visible = True
        self.cursor_timer = None
        self.cursorPositionChanged.connect(self.cursorPositionChange)



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
    def AdjustLineEditWidth(self,):
        # 获取当前字体
        font = self.font()
        # 创建 QFontMetrics 对象
        font_metrics = QtGui.QFontMetrics(font)
        text = self.text()
        text_width = font_metrics.width(text)
        extra_padding =  5
        total_width = text_width + extra_padding

        # 设置 QLineEdit 的最大宽度
        self.setMaximumWidth(total_width)

    # 设置样式
    def setStyle(self):
        super(ReadOnlyLineEdit, self).setStyleSheet(f"border-left: 2px solid;selection-color:{TEXT_SELECTED_COLOR};selection-background-color:{TEXT_SELECTED_BACKGROUND_COLOR};border: none;background-color: {self.linebgcolor};color: {self.linecolor}")


    def EditLine(self, text,color=None):
        self.blockSignals(True)
        self.setText(text)
        self.blockSignals(False)

    def InsertText(self, text,color=None):
        origin_text = self.text()
        self.EditLine(origin_text + text)


    def GetLine(self):
        return self.text()

    def SetColor(self, color):
        if(isinstance(color,str)):
            self.linecolor = color
        elif(isinstance(color,int)):
            self.linecolor = "#" + "%06X"%color



    def SetbgColor(self, color):
        if(isinstance(color,str)):
            self.linebgcolor = color
        elif(isinstance(color,int)):
            self.linebgcolor = "#" + "%06X"%color

    def GetbgColor(self):
        return self.linebgcolor

    
    def Clear(self):
        self.EditLine("")
        self.SetColor(DEFINE_LINE_COLOR)
        self.SetbgColor(TRANSPARENT)


    def Refresh(self):
        self.setStyle()
        self.AdjustLineEditWidth()


    def mouseDoubleClickEvent(self, event):
        super().mouseDoubleClickEvent(event)
        current_text = self.text()
        self.table_parent.WidgeDoubleClick(current_text)
        



class ReadOnlyTextEdit(QtWidgets.QTextEdit):
    def __init__(self, text=None, parent=None):
        super(ReadOnlyTextEdit, self).__init__(parent)
        if(not isinstance(parent,StackContainer)):
            raise("parent widge class must be StackContainer")
        self.table_parent = parent
        self.setReadOnly(True)
        self.setFont(QtGui.QFont(TEXT_FONT, TEXT_FONT_SIZE))
        # 禁止换行
        self.setLineWrapMode(self.NoWrap)
        self.setAutoFormatting(self.AutoNone)
        # 设置固定高度
        self.setFixedHeight(27)
        # 禁用垂直滚动条
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        # 禁用水平滚动条
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)





        self.linecolor = DEFINE_LINE_COLOR
        self.linebgcolor = TRANSPARENT

        self._cursor_visible = True
        self.cursor_timer = None

        if text:
            self.EditLine(text)


        self.installEventFilter(self)
        self.cursorPositionChanged.connect(self.cursorPositionChange)

    def wheelEvent(self, event):
        # 忽略鼠标滚轮事件
        event.ignore()



    def keyPressEvent(self, event):
        if event.key() in (QtCore.Qt.Key_Left, QtCore.Qt.Key_Right):
            cursor = self.textCursor()
            if event.modifiers() & QtCore.Qt.ShiftModifier:
                # 按下 Shift 键时进行选择
                cursor.movePosition({
                    QtCore.Qt.Key_Left: QtGui.QTextCursor.Left,
                    QtCore.Qt.Key_Right: QtGui.QTextCursor.Right,
                }[event.key()], QtGui.QTextCursor.KeepAnchor)
            else:
                # 不按 Shift 键时仅移动光标
                cursor.movePosition({
                    QtCore.Qt.Key_Left: QtGui.QTextCursor.Left,
                    QtCore.Qt.Key_Right: QtGui.QTextCursor.Right,
                }[event.key()])
            self.setTextCursor(cursor)
        if event.key() in (QtCore.Qt.Key_Up, QtCore.Qt.Key_Down):
            # 将上下方向键事件传递给父控件
            if self.parent():
                self.parent().keyPressEvent(event)
            return
        # 全选 和 复制
        elif event.matches(QtGui.QKeySequence.Copy) or event.matches(QtGui.QKeySequence.SelectAll):
            super().keyPressEvent(event)
            return



    def eventFilter(self, obj, event):
        if (obj is self and event.type() in [QtCore.QEvent.InputMethodQuery,QtCore.QEvent.Wheel] ):
            self.viewport().setCursor(QtCore.Qt.ArrowCursor) 
            self.verticalScrollBar().setValue(4)
        return False


    # 保持箭头光标样式
    def enterEvent(self, event):
        self.viewport().setCursor(QtCore.Qt.ArrowCursor) 
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.viewport().setCursor(QtCore.Qt.ArrowCursor) 
        super().leaveEvent(event)


    def focusInEvent(self, event):
        super(ReadOnlyTextEdit, self).focusInEvent(event)
        self.cursorPositionChange()
        if self.table_parent:
            cursor = self.textCursor()
            cursor.movePosition(QtGui.QTextCursor.Right, QtGui.QTextCursor.MoveAnchor, self.table_parent.cursor_position)
            self.setTextCursor(cursor)
        
        if not self.cursor_timer:
            self.cursor_timer = self.startTimer(500) 

    def focusOutEvent(self, event):
        super(ReadOnlyTextEdit, self).focusOutEvent(event)
        cursor = self.textCursor()
        cursor.clearSelection()
        self.setTextCursor(cursor)
        if self.table_parent:
            self.table_parent.cursor_position = self.textCursor().position()
        if self.cursor_timer is not None:
            self.killTimer(self.cursor_timer)
            self.cursor_timer = None
        self._cursor_visible = False
        self.update()

    def cursorPositionChange(self, event=None):
        if self.cursor_timer is not None:
            self.killTimer(self.cursor_timer)
        self._cursor_visible = True
        self.cursor_timer = self.startTimer(500)

    def timerEvent(self, event):
        if self.cursor_timer == event.timerId():
            self._cursor_visible = not self._cursor_visible
            self.viewport().update()
        super(ReadOnlyTextEdit, self).timerEvent(event)

    def paintEvent(self, event):
        super(ReadOnlyTextEdit, self).paintEvent(event)
        if self.isReadOnly() and self.hasFocus() and self._cursor_visible and not self.toPlainText().strip() == '':
            painter = QtGui.QPainter(self.viewport())
            cursor_rect = self.cursorRect()
            painter.fillRect(cursor_rect.left(), cursor_rect.top(), 2, cursor_rect.height(), QtGui.QColor('black'))

    def contextMenuEvent(self, event):
        global_pos = self.mapToGlobal(event.pos())
        if self.table_parent:
            self.table_parent.show_context_menu(global_pos)

    def AdjustTextEditWidth(self):
        font = self.font()
        font_metrics = QtGui.QFontMetrics(font)
        lines = self.toPlainText().splitlines()
        max_text_width = max([font_metrics.width(line) for line in lines]) if lines else 0
        extra_padding = 8
        total_width = max_text_width + extra_padding
        self.setMaximumWidth(total_width)

        cursor = self.textCursor()
        cursor.setPosition(0)
        self.setTextCursor(cursor)


    def setStyle(self):
        style_sheet = f"""
            QTextEdit {{
                selection-color: {TEXT_SELECTED_COLOR};
                selection-background-color: {TEXT_SELECTED_BACKGROUND_COLOR};
                border: none;
                background-color: {self.linebgcolor};
                color: {self.linecolor};
            }}
        """
        self.setStyleSheet(style_sheet)

    def EditLine(self, text, color = None):
        if(color == None):
            color = self.linecolor
        cursor = self.textCursor()
        cursor.select(QtGui.QTextCursor.LineUnderCursor)
        cursor.removeSelectedText()
        format = QtGui.QTextCharFormat()
        if isinstance(color, str):
                    format.setForeground(QtGui.QColor(color))
        elif isinstance(color, int):
            format.setForeground(QtGui.QColor("#" + "%06X" % color))
        cursor.mergeCharFormat(format)


        cursor.insertText(text)
        

    def InsertText(self, text, color = None):
        if(color == None):
            color = self.linecolor
        cursor = self.textCursor()
        cursor.movePosition(cursor.End)
        self.setTextCursor(cursor)

        format = QtGui.QTextCharFormat()
        if isinstance(color, str):
                    format.setForeground(QtGui.QColor(color))

        elif isinstance(color, int):
            format.setForeground(QtGui.QColor("#" + "%06X" % color))
        cursor.mergeCharFormat(format)
        cursor.insertText(text)


    def GetLine(self):
        return self.toPlainText()

    def SetColor(self, color):
        if isinstance(color, str):
            self.linecolor = color
        elif isinstance(color, int):
            self.linecolor = "#" + "%06X" % color

    def SetbgColor(self, color):
        if isinstance(color, str):
            self.linebgcolor = color
        elif isinstance(color, int):
            self.linebgcolor = "#" + "%06X" % color

    def GetbgColor(self):
        return self.linebgcolor

    def Clear(self):
        self.EditLine("")
        self.SetColor(DEFINE_LINE_COLOR)
        self.SetbgColor(TRANSPARENT)

    def Refresh(self):
        self.setStyle()
        self.AdjustTextEditWidth()

    def mouseDoubleClickEvent(self, event):
        super().mouseDoubleClickEvent(event)
        
        cursor = self.textCursor()
        if cursor.hasSelection():
            selected_text = cursor.selectedText()
            self.table_parent.WidgeDoubleClick(selected_text)
        

class StackContainer(QtWidgets.QWidget):
    def __init__(self,parent,bitness=64,parent_viewer = None):
        super(StackContainer,self).__init__(parent)
        self.parent_viewer = parent_viewer
        self.bitness = bitness
        self.backgroundColor = DEFINE_BACKGROUND_COLOR 

        self.cursor_position = 0   # 指针位置
        self.address_id = []   # 行 -> 地址 
        self.widget_dict = {}   # 控件名 -> 控件
        self.highlighting = []   # 当前高亮的控件
        self.waittorefresh = []
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

        horizontalHeader.resizeSection(4,500)

        horizontalHeader.resizeSection(5,60)
        horizontalHeader.setSectionResizeMode(5,QtWidgets.QHeaderView.Fixed) 
        horizontalHeader.resizeSection(6, 60)
        horizontalHeader.setSectionResizeMode(6,QtWidgets.QHeaderView.Fixed) 



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


    def showEvent(self, event):
        self.parent_viewer.RefreshStackContainer()
        super().showEvent(event) 


    def contextMenuEvent(self, event):
        self.show_context_menu(self.mapToGlobal(event.pos()))


    def show_context_menu(self, pos):
        # 创建上下文菜单
        menu = QtWidgets.QMenu(self)

        # 添加菜单项
        action1 = QtWidgets.QAction('Refresh Window', self)
        action2 = QtWidgets.QAction('Reinitialize the window', self)

        # 连接菜单项的触发事件
        action1.triggered.connect(self.RefreshWindow)
        action2.triggered.connect(self.ReinitializeWindows)

        # 添加菜单项到菜单
        menu.addAction(action1)
        menu.addAction(action2)

        # 显示菜单
        menu.exec_(pos)


    def RefreshWindow(self):
        horizontalHeader = self.table_widget.horizontalHeader()
        horizontalHeader.resizeSection(0,76)
        horizontalHeader.resizeSection(0,75)
        
        for edit in self.waittorefresh:
            edit.Refresh()
        self.waittorefresh.clear()


    def ReinitializeWindows(self):
        self.parent_viewer.InitStackContainer()


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
        #获取当前选中的列
        #获取当前选中的行
        selected_items = [self.table_widget.cellWidget(self.table_widget.currentRow(),self.table_widget.currentColumn())]
        if not selected_items:
            return False
        
        if(selected_items[0] != None):
            selected_value = selected_items[0].GetLine()

            # # 高亮所有值相同的单元格
            if(selected_value != ""):
                for item in self.widget_dict:
                    if(self.widget_dict[item].GetLine() == selected_value and isinstance(self.widget_dict[item],ReadOnlyLineEdit) ):
                        originalcolor = self.widget_dict[item].GetbgColor()
                        self.widget_dict[item].SetbgColor(0xFFFF33)
                        self.highlighting.append([item,originalcolor])
                        self.waittorefresh.append(self.widget_dict[item])
        self.RefreshWindow()
        return True


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
            print("Existing address")
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
                # print("[DeleteLine] Address not found")
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


    def ClearItme(self,Address,Header):
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
                # print("[RolltoAddress] Address not found")
                return False
        # 找到对应地址的行索引
        row_index = self.address_id.index(Address)
        self.table_widget.scrollToItem(self.table_widget.item(row_index, 0),self.table_widget.PositionAtTop)



    def GetAddressRange(self):
        if(self.address_id != []):
            return self.address_id[0], self.address_id[len(self.address_id)-1]
        else:
            return -1,-1
        

    def EnableUpdates(self):
        self.table_widget.setUpdatesEnabled(True)

    def DisableUpdates(self):
        self.table_widget.setUpdatesEnabled(False)


    def WidgeDoubleClick(self,selected_data): 
        self.parent_viewer.WidgeDoubleClick(selected_data)


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