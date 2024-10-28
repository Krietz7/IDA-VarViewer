
from PyQt5 import QtWidgets,QtGui,Qt,QtCore
from PyQt5.QtCore import Qt



from StackView.Defines import *


class ReadOnlyLineEdit(QtWidgets.QLineEdit):
    def __init__(self,text=None,parent=None):
        super(ReadOnlyLineEdit, self).__init__(text,parent)
        # 初始化
        self.table_parent = parent   # 父控件
        self.setReadOnly(True)
        self.setFont(QtGui.QFont(TEXT_FONT, TEXT_FONT_SIZE))

        # 有默认值的属性
        self.linecolor = DEFINE_LINE_COLOR
        self.linebgcolor = TRANSPARENT

        # 属性
        self._cursor_visible = True
        self.cursor_timer = None
        self.cursorPositionChanged.connect(self.cursorPositionChange)



    # 聚焦在窗口时绘制并显示光标
    def focusInEvent(self, event):
        super(ReadOnlyLineEdit, self).focusInEvent(event)
        self.cursorPositionChange()
        if(hasattr(self.table_parent,"cursor_position")):
            self.setCursorPosition(self.table_parent.cursor_position)
        
        if not self.cursor_timer:
            self.cursor_timer = self.startTimer(500) 

    def focusOutEvent(self, event):
        super(ReadOnlyLineEdit, self).focusOutEvent(event)
        if(hasattr(self.table_parent,"cursor_position")):
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

    # 右键菜单：打开父控件的菜单
    def contextMenuEvent(self, event):
        # 将局部坐标转换为全局坐标
        global_pos = self.mapToGlobal(event.pos())
        # 调用表格的右键菜单显示方法
        if(hasattr(self.table_parent,"show_context_menu")):
            self.table_parent.show_context_menu(global_pos)

    # 双击事件：发送被双击的文本到父控件
    def mouseDoubleClickEvent(self, event):
        super().mouseDoubleClickEvent(event)
        current_text = self.text()
        self.table_parent.WidgeDoubleClick(current_text)
        
    # 更新文本框宽度
    def __adjust_line_edit_width(self,):
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
    def __set_style(self):
        super(ReadOnlyLineEdit, self).setStyleSheet(f"border-left: 2px solid;selection-color:{TEXT_SELECTED_COLOR};selection-background-color:{TEXT_SELECTED_BACKGROUND_COLOR};border: none;background-color: {self.linebgcolor};color: {self.linecolor}")


    # 公用方法
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
        self.__set_style()
        self.__adjust_line_edit_width()

