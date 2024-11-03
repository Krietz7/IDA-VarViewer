from PyQt5 import QtWidgets,QtGui,Qt,QtCore
from PyQt5.QtCore import Qt

from StackView.Config import *





class ReadOnlyTextEdit(QtWidgets.QTextEdit):
    def __init__(self, text=None, parent=None):
        super(ReadOnlyTextEdit, self).__init__(parent)

        # 初始化
        self.table_parent = parent
        self.setReadOnly(True)
        self.setFont(QtGui.QFont(TEXT_FONT, TEXT_FONT_SIZE))
        self.setLineWrapMode(self.NoWrap)
        self.setAutoFormatting(self.AutoNone)
        self.setFixedHeight(27)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)




        # 有默认值的属性
        self.linecolor = DEFINE_LINE_COLOR
        self.linebgcolor = TRANSPARENT

        # 属性
        self._cursor_visible = True
        self.cursor_timer = None

        if text:
            self.EditLine(text)


        self.installEventFilter(self)
        self.cursorPositionChanged.connect(self.cursorPositionChange)

    # 忽略鼠标滚轮事件
    def wheelEvent(self, event):
        event.ignore()

    # 重写使用键盘移动光标方法
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

    # 聚焦在窗口时绘制并显示光标
    def focusInEvent(self, event):
        super(ReadOnlyTextEdit, self).focusInEvent(event)
        self.cursorPositionChange()
        if(hasattr(self.table_parent,"cursor_position")):
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
        if(hasattr(self.table_parent,"cursor_position")):
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

    # 右键菜单：打开父控件的菜单
    def contextMenuEvent(self, event):
        global_pos = self.mapToGlobal(event.pos())
        if(hasattr(self.table_parent,"show_context_menu")):
            self.table_parent.show_context_menu(global_pos,self)

    # 双击事件：发送被双击的文本到父控件
    def mouseDoubleClickEvent(self, event):
        super().mouseDoubleClickEvent(event)
        
        cursor = self.textCursor()
        if (cursor.hasSelection() and hasattr(self.table_parent,"WidgeDoubleClick")):
            selected_text = cursor.selectedText()
            self.table_parent.WidgeDoubleClick(selected_text)

    def __scroll_to_start(self):
        """将 QTextEdit 滚动到最左侧"""
        cursor = self.textCursor()
        cursor.movePosition(QtGui.QTextCursor.Start)
        self.setTextCursor(cursor)
        self.ensureCursorVisible()  # 确保光标可见


    def __adjust_line_edit_width(self):
        font = self.font()
        font_metrics = QtGui.QFontMetrics(font)
        lines = self.toPlainText().splitlines()
        max_text_width = max([font_metrics.width(line) for line in lines]) if lines else 0
        extra_padding = 8
        total_width = max_text_width + extra_padding
        self.setMaximumWidth(total_width)

    def __set_style(self):
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
        self.__set_style()
        # self.__adjust_line_edit_width()
        self.__scroll_to_start()