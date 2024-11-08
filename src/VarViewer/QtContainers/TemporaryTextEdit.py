from PyQt5.QtWidgets import QTextEdit,QMainWindow,QWidget,QVBoxLayout
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt

from VarViewer.config import *


class TemporaryTextEdit(QTextEdit):
    def __init__(self, text=None, parent=None,bgcolor=None,linecolor=None):
        super().__init__(text,parent)
        self.table_parent = parent
        self.setGeometry(300, 300, 400, 200)
        self.setReadOnly(True)
        self.setFont(QFont(TEXT_FONT, TEXT_FONT_SIZE))
        self.setStyleSheet(f"""selection-color:{TEXT_SELECTED_COLOR};
                            selection-background-color:{TEXT_SELECTED_BACKGROUND_COLOR};
                            border: none;background-color: {bgcolor};color: {linecolor};
                            """)

    # Double-click: Send the selected text to the parent widget
    def mouseDoubleClickEvent(self, event):
        super().mouseDoubleClickEvent(event)
        cursor = self.textCursor()
        if (cursor.hasSelection() and hasattr(self.table_parent,"widget_double_click")):
            selected_text = cursor.selectedText()
            self.table_parent.widget_double_click(selected_text)

    # Keep cursor style
    def enterEvent(self, event):
        self.viewport().setCursor(Qt.ArrowCursor)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.viewport().setCursor(Qt.ArrowCursor)
        super().leaveEvent(event)


class TemporaryItemViewer(QMainWindow):
    def __init__(self, parent, item):
        super().__init__(parent)
        self.setWindowTitle(item.objectName())
        self.setGeometry(300, 300, 400, 200)

        central_widget = QWidget(self)
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(item)

        self.setCentralWidget(central_widget)
