
from PyQt5 import QtWidgets,QtGui,QtCore
from StackView.Config import *



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