import idaapi

from PyQt5 import QtWidgets,QtGui,Qt,QtCore
from PyQt5.QtCore import Qt

from StackView.Defines import *
from StackView.QtContainers.ReadOnlyLineEdit import ReadOnlyLineEdit
from StackView.QtContainers.ReadOnlyTextEdit import ReadOnlyTextEdit


class VaribleContainer(QtWidgets.QWidget):
    def __init__(self,parent,bitness=64,parent_viewer = None):
        pass