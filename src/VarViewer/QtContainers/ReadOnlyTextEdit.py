from PyQt5.QtWidgets import QTextEdit
from PyQt5.QtGui import QFont,QTextCursor,QKeySequence,QPainter,QColor,QTextCharFormat
from PyQt5.QtCore import Qt,QEvent

from VarViewer.config import *





class ReadOnlyTextEdit(QTextEdit):
    def __init__(self, text=None, parent=None):
        super().__init__(parent)
        # Initialize
        self.parent = parent
        self.setReadOnly(True)
        self.setFont(QFont(TEXT_FONT, TEXT_FONT_SIZE))
        self.setLineWrapMode(self.NoWrap)
        self.setAutoFormatting(self.AutoNone)
        self.setFixedHeight(27)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.installEventFilter(self)
        self.cursorPositionChanged.connect(self._cursor_position_change)

        # Private properties
        self._cursor_visible = True
        self.cursor_timer = None

        # Properties with default values, can be overridden by methods
        self.line_color = DEFINE_LINE_COLOR
        self.line_bgcolor = TRANSPARENT

        if text:
            self.edit_line(text)

    # Ignore mouse wheel events
    def wheelEvent(self, event):
        event.ignore()

    def keyPressEvent(self, event):
        '''Rewrite the method to move the cursor using the keyboard'''
        if event.key() in (Qt.Key_Left, Qt.Key_Right):
            cursor = self.textCursor()
            if event.modifiers() & Qt.ShiftModifier:
                # Select while holding down the Shift key
                move_mode = QTextCursor.KeepAnchor
            else:
                # Move cursor only without pressing Shift
                move_mode = QTextCursor.MoveAnchor

            if event.modifiers() & Qt.ControlModifier:
                # Move by word with Ctrl key
                if event.key() == Qt.Key_Left:
                    cursor.movePosition(QTextCursor.PreviousWord, move_mode)
                elif event.key() == Qt.Key_Right:
                    cursor.movePosition(QTextCursor.NextWord, move_mode)
            else:
                # Normal movement
                cursor.movePosition({
                    Qt.Key_Left: QTextCursor.Left,
                    Qt.Key_Right: QTextCursor.Right,
                }[event.key()], move_mode)
            self.setTextCursor(cursor)

        elif event.key() in (Qt.Key_Up, Qt.Key_Down):
            # Pass up and down arrow key events to the parent widget
            if self.parent:
                self.parent.keyPressEvent(event)
            return
        # Select All and Copy
        elif event.matches(QKeySequence.Copy) or event.matches(QKeySequence.SelectAll):
            super().keyPressEvent(event)
            return

    def eventFilter(self, obj, event):
        '''keep verticalScrollBar at 4'''
        if (obj is self and event.type() in [QEvent.InputMethodQuery,QEvent.Wheel] ):
            self.viewport().setCursor(Qt.ArrowCursor)
            self.verticalScrollBar().setValue(4)
        return False

    def enterEvent(self, event):
        '''keep cursor as Qt.ArrowCursor'''
        self.viewport().setCursor(Qt.ArrowCursor)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.viewport().setCursor(Qt.ArrowCursor)
        super().leaveEvent(event)

    def focusInEvent(self, event):
        '''Draw and show the cursor when the window is focused'''
        super().focusInEvent(event)
        self._cursor_position_change()
        if hasattr(self.parent,"cursor_position"):
            cursor = self.textCursor()
            cursor.movePosition(QTextCursor.Right, QTextCursor.MoveAnchor,\
                                self.parent.cursor_position)
            self.setTextCursor(cursor)

        if not self.cursor_timer:
            self.cursor_timer = self.startTimer(500)

    def focusOutEvent(self, event):
        super().focusOutEvent(event)
        cursor = self.textCursor()
        cursor.clearSelection()
        self.setTextCursor(cursor)
        if hasattr(self.parent,"cursor_position"):
            self.parent.cursor_position = self.textCursor().position()
        if self.cursor_timer is not None:
            self.killTimer(self.cursor_timer)
            self.cursor_timer = None
        self._cursor_visible = False
        self.update()


    def timerEvent(self, event):
        if self.cursor_timer == event.timerId():
            self._cursor_visible = not self._cursor_visible
            self.viewport().update()
        super().timerEvent(event)

    def paintEvent(self, event):
        super().paintEvent(event)
        if self.isReadOnly() and self.hasFocus() and self._cursor_visible\
           and not self.toPlainText().strip() == '':
            painter = QPainter(self.viewport())
            cursor_rect = self.cursorRect()
            painter.fillRect(cursor_rect.left(), cursor_rect.top(), 2,\
                             cursor_rect.height(), QColor('black'))

    def contextMenuEvent(self, event):
        '''Right-click: Open the menu of the parent widget'''
        global_pos = self.mapToGlobal(event.pos())
        if hasattr(self.parent,"show_context_menu"):
            self.parent.show_context_menu(global_pos,self)

    def mouseDoubleClickEvent(self, event):
        '''Double-click: Send the selected text to the parent widget'''
        super().mouseDoubleClickEvent(event)

        cursor = self.textCursor()
        if (cursor.hasSelection() and hasattr(self.parent,"widget_double_click")):
            selected_text = cursor.selectedText()
            self.parent.widget_double_click(selected_text)

    def _cursor_position_change(self, event=None):
        if self.cursor_timer is not None:
            self.killTimer(self.cursor_timer)
        self._cursor_visible = True
        self.cursor_timer = self.startTimer(500)

    def _scroll_to_start(self):
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.Start)
        self.setTextCursor(cursor)
        self.ensureCursorVisible()

    def _set_style(self):
        style_sheet = f"""
            QTextEdit {{
                selection-color: {TEXT_SELECTED_COLOR};
                selection-background-color: {TEXT_SELECTED_BACKGROUND_COLOR};
                border: none;
                background-color: {self.line_bgcolor};
                color: {self.line_color};
            }}
        """
        self.setStyleSheet(style_sheet)

    def edit_line(self, text, color = None):
        if color is None:
            color = self.line_color

        cursor = self.textCursor()
        cursor.select(QTextCursor.LineUnderCursor)
        cursor.removeSelectedText()

        format_ = QTextCharFormat()
        if isinstance(color, str):
            format_.setForeground(QColor(color))
        elif isinstance(color, int):
            format_.setForeground(QColor(f'#{color:06X}'))

        cursor.mergeCharFormat(format_)
        cursor.insertText(text)


    def insert_text(self, text, color = None):
        if color is None:
            color = self.line_color

        cursor = self.textCursor()
        cursor.movePosition(cursor.End)
        self.setTextCursor(cursor)

        format_ = QTextCharFormat()
        if isinstance(color, str):
            format_.setForeground(QColor(color))
        elif isinstance(color, int):
            format_.setForeground(QColor(f'#{color:06X}'))

        cursor.mergeCharFormat(format_)
        cursor.insertText(text)


    def get_line(self):
        return self.toPlainText()

    def set_color(self, color):
        if isinstance(color, str):
            self.line_color = color
        elif isinstance(color, int):
            self.line_color = f'#{color:06X}'

    def set_bgcolor(self, color):
        if isinstance(color, str):
            self.line_bgcolor = color
        elif isinstance(color, int):
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
