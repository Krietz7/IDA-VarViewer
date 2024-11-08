from PyQt5.QtWidgets import QLineEdit
from PyQt5.QtGui import QFont,QPainter,QColor

from VarViewer.config import *



class ReadOnlyLineEdit(QLineEdit):
    def __init__(self,text,parent,line_id = None):
        super().__init__(text,parent)
        # Initialize
        self.parent = parent
        self.line_id = line_id
        self.setReadOnly(True)
        self.setFont(QFont(TEXT_FONT, TEXT_FONT_SIZE))

        # Private properties
        self._cursor_visible = True
        self._cursor_timer = None
        self.cursorPositionChanged.connect(self._cursor_position_change)

        # Properties with default values, can be overridden by methods
        self.line_color = DEFINE_LINE_COLOR
        self.line_bgcolor = TRANSPARENT

    def focusInEvent(self, event):
        '''Draw and show the cursor when the window is focused'''
        super().focusInEvent(event)
        self._cursor_position_change()
        if hasattr(self.parent,"cursor_position"):
            self.setCursorPosition(self.parent.cursor_position)

        if not self._cursor_timer:
            self._cursor_timer = self.startTimer(500)

    def focusOutEvent(self, event):
        super().focusOutEvent(event)
        if hasattr(self.parent,"cursor_position"):
            self.parent.cursor_position = self.cursorPosition()
        if self._cursor_timer is not None:
            self.killTimer(self._cursor_timer)
            self._cursor_timer = None
        self._cursor_visible = False
        self.update()

    def timerEvent(self, event):
        if self._cursor_timer == event.timerId():
            self._cursor_visible = not self._cursor_visible
            self.update()
        super().timerEvent(event)

    def paintEvent(self, event):
        super().paintEvent(event)
        text = self.text()
        if self.isReadOnly() and self.hasFocus() and self._cursor_visible and text != '':
            painter = QPainter(self)
            cursor_pos = self.cursorRect().left()
            cursor_height = self.cursorRect().height()
            painter.fillRect(cursor_pos+4, 0, 2, cursor_height+10,QColor('black'))

    def contextMenuEvent(self, event):
        '''Right-click: Open the menu of the parent widget'''
        global_pos = self.mapToGlobal(event.pos())
        if hasattr(self.parent,"show_context_menu"):
            self.parent.show_context_menu(global_pos,self)

    def mouseDoubleClickEvent(self, event):
        '''Double-click: Send the selected text to the parent widget'''
        super().mouseDoubleClickEvent(event)
        current_text = self.selectedText()
        if hasattr(self.parent,"widget_double_click"):
            self.parent.widget_double_click(current_text)

    def _cursor_position_change(self, event=None):
        if self._cursor_timer is not None:
            self.killTimer(self._cursor_timer)
        self._cursor_visible = True
        self._cursor_timer = self.startTimer(500)

    def _scroll_to_start(self):
        self.setCursorPosition(0)

    def _set_style(self):
        super().setStyleSheet(\
            f"""border-left: 2px solid;selection-color:{TEXT_SELECTED_COLOR};
            selection-background-color:{TEXT_SELECTED_BACKGROUND_COLOR};
            border: none;background-color:{self.line_bgcolor};color:{self.line_color}""")

    def edit_line(self, text, color=None):
        self.blockSignals(True)
        self.setText(text)
        self.blockSignals(False)

    def insert_text(self, text, color=None):
        origin_text = self.text()
        self.edit_line(origin_text + text)

    def get_line(self):
        return self.text()

    def set_color(self, color):
        if isinstance(color,str):
            self.line_color = color
        elif isinstance(color,int):
            self.line_color = f'#{color:06X}'

    def set_bgcolor(self, color):
        if isinstance(color,str):
            self.line_bgcolor = color
        elif isinstance(color,int):
            self.line_bgcolor = f'#{color:06X}'

    def get_bgcolor(self):
        return self.line_bgcolor

    def clear(self):
        self.edit_line("")
        self.set_color(DEFINE_LINE_COLOR)
        self.set_bgcolor(TRANSPARENT)

    def refresh(self):
        self._set_style()
        self._scroll_to_start()
