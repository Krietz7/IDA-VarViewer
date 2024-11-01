import idaapi

from PyQt5 import QtWidgets,QtGui,Qt,QtCore
from PyQt5.QtCore import Qt

from StackView.Config import *
from StackView.QtContainers.ReadOnlyLineEdit import ReadOnlyLineEdit
from StackView.QtContainers.ReadOnlyTextEdit import ReadOnlyTextEdit


class VariableContainer(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super(VariableContainer, self).__init__(parent)
        
        self.tree_widget = QtWidgets.QTreeWidget(self)
        self.tree_widget.setIndentation(15)  # 设置缩进
        self.tree_widget.setUniformRowHeights(True)

        # 设置表头
        self.tree_widget.setHeaderHidden(False)  
        self.tree_widget.setColumnCount(5)  
        self.tree_widget.setHeaderLabels(['Name', 'Type', 'Value','Address', 'Remark'])
        horizontalHeader = self.tree_widget.horizontalScrollBar()
        
        self.tree_widget.setColumnWidth(0, 400)
        self.tree_widget.setColumnWidth(1, 250)
        self.tree_widget.setColumnWidth(2, 300)
        self.tree_widget.setColumnWidth(3, 450)
        self.tree_widget.setColumnWidth(4, 200)





        self.backgroundcolor = DEFINE_BACKGROUND_COLOR
        self.topItemsDict = {}  # 保存结构： { topitemid : [item, itemdict: {itemid : item}],  ......   }
        self.waittorefresh = []




        # 初始化树形结构
        self.init_tree()

        # 设置布局
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.tree_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)


    def init_tree(self):
        self.reset_QSS()
        self.tree_widget.setAlternatingRowColors(True)

       
    def reset_QSS(self):
        
        self.tree_widget.setStyleSheet(f"""    
            QTreeWidget {{
                alternate-background-color: {DEBUG_BACKGROUND_LINE_COLOR2};
                background-color: {self.backgroundcolor};
            }}
            QTreeView QHeaderView::section{{
                background:{QHEADER_BACKGROUND_COLOR};
                height:30px;
                border: none;
            }}
            QTreeView::item {{
                height: 27px;
            }}
            QTreeWidget::item:selected {{
                background-color: {SELECTED_ITEM_BACKGROUND_COLOR};
                border: none;
            }}
            """)                             



    def contextMenuEvent(self, event):
        self.show_context_menu(self.mapToGlobal(event.pos()))

    def show_context_menu(self, pos, item = None):
        # 创建上下文菜单
        menu = QtWidgets.QMenu(self)

        # 添加菜单项
        action1 = QtWidgets.QAction('action1', self)
        action2 = QtWidgets.QAction('action2', self)
        action3 = QtWidgets.QAction('action3', self)

        # 连接菜单项的触发事件
        # action1.triggered.connect(self.RefreshWindow)
        # action2.triggered.connect(self.ReinitializeWindows)
        # action3.triggered.connect(lambda: self.ShowTheItem(item))

        # 添加菜单项到菜单
        menu.addAction(action1)
        menu.addAction(action2)
        menu.addAction(action3)

        # 显示菜单
        menu.exec_(pos)

    # 展开所有子节点
    def expand_all_nodes(self):
        def expand_recursively(item):
            item.setExpanded(True)
            for i in range(item.childCount()):
                child = item.child(i)
                expand_recursively(child)

        for i in range(self.tree_widget.topLevelItemCount()):
            top_level_item = self.tree_widget.topLevelItem(i)
            expand_recursively(top_level_item)


    def fold_all_nodes(self):
        def fold_recursively(item):
            item.setExpanded(False)
            for i in range(item.childCount()):
                child = item.child(i)
                fold_recursively(child)

        # 遍历顶级项并递归地折叠所有子节点
        for i in range(self.tree_widget.topLevelItemCount()):
            top_level_item = self.tree_widget.topLevelItem(i)
            fold_recursively(top_level_item)



    def RefreshWindow(self):
        for edit in self.waittorefresh:
            edit.Refresh()
        self.waittorefresh.clear()
        self.tree_widget.setColumnWidth(0, 299)
        self.tree_widget.setColumnWidth(0, 300)

    # 添加顶层项目到树中
    # itemID: 父项在父项列表中的唯一标识符
    def add_top_level_item(self,itemID,itemName,color=None):
        if(itemID in self.topItemsDict.keys()):
            return False # 该顶层项目已存在，不再添加

        item = QtWidgets.QTreeWidgetItem()  # 创建一个四列的项
        self.tree_widget.addTopLevelItem(item)

        itemname_edit = ReadOnlyLineEdit(itemName,self)
        itemname_edit.SetbgColor(TRANSPARENT)
        itemname_edit.Refresh()
        if(color != None):
            itemname_edit.SetColor(color)

        self.tree_widget.setItemWidget(item, 0, itemname_edit)

        self.topItemsDict[itemID] = [item,{}]
        self.waittorefresh.append(itemname_edit)
        return True





    # 为顶层项目添加子节点
    def add_func_items(self,parentitemID,itemID,itemName,color=None):
        if(parentitemID not in self.topItemsDict.keys()):
            return False # 该父项在父项列表中不存在
        elif(itemID in self.topItemsDict[parentitemID][1]):
            return False # 该父项在二级列表中已存在

        parentitem = self.topItemsDict[parentitemID][0]
        item = QtWidgets.QTreeWidgetItem()  # 创建一个四列的项
        parentitem.insertChild(0,item)

        itemname_edit = ReadOnlyLineEdit(itemName,self)
        itemname_edit.SetbgColor(TRANSPARENT)
        itemname_edit.Refresh()
        if(color != None):
            itemname_edit.SetColor(color)

        self.tree_widget.setItemWidget(item, 0, itemname_edit)

        self.topItemsDict[parentitemID][1][itemID] = [item,{}]
        self.waittorefresh.append(itemname_edit)
        return True


    def add_variable_line(self, topitemID, parentitemID, Varname, Type=None, value=None, Address=None, Remark=None, Color=None):
        if(topitemID not in self.topItemsDict.keys()):
            return False # 该父项在顶级列表中不存在
        elif(parentitemID not in self.topItemsDict[topitemID][1]):
            return False # 该父项在二级列表中不存在

        parentitem = self.topItemsDict[topitemID][1][parentitemID][0]
        editdict = self.topItemsDict[topitemID][1][parentitemID][1]
        editdict[Varname] = []


        item = QtWidgets.QTreeWidgetItem()  # 创建一个四列的项
        parentitem.addChild(item)


        
        Editlist = [ReadOnlyLineEdit(Varname,self),ReadOnlyLineEdit(Type,self),ReadOnlyLineEdit(value,self),ReadOnlyTextEdit(Address,self), ReadOnlyLineEdit(Remark,self)]  
        ColorList = [VAR_NAME_COLOR,VAR_TYPE_COLOR,VAR_VALUE_COLOR,VAR_ADDR_COLOR,VAR_REMARK_COLOR]
        if(Color != None):
            ColorList[0] = Color
        self.waittorefresh += Editlist

        for i in range(len(Editlist)):
            edit = Editlist[i]
            color = ColorList[i]
            
            edit.SetbgColor(TRANSPARENT)
            edit.SetColor(color)
            edit.Refresh()

            editdict[Varname] += [edit]

            self.tree_widget.setItemWidget(item, i, edit)
        return True



    def EditVaribleInfo(self, topitemID, parentitemID, Varname, Header, Text, color=None):
        if(topitemID not in self.topItemsDict.keys()):
            return  # 该父项在顶级列表中不存在
        elif(parentitemID not in self.topItemsDict[topitemID][1]):
            return # 该父项在二级列表中不存在

        editdict = self.topItemsDict[topitemID][1][parentitemID][1]
        targetedit = editdict[Varname][Header]

        targetedit.EditLine(Text,color)
        targetedit.Refresh()
        self.waittorefresh.append(targetedit)
        

    def InsertVaribleInfo(self, topitemID, parentitemID, Varname, Header, Text, color=None):
        if(topitemID not in self.topItemsDict.keys()):
            return  # 该父项在顶级列表中不存在
        elif(parentitemID not in self.topItemsDict[topitemID][1]):
            return # 该父项在二级列表中不存在

        editdict = self.topItemsDict[topitemID][1][parentitemID][1]
        targetedit = editdict[Varname][Header]

        targetedit.InsertText(Text,color)
        targetedit.Refresh()
        self.waittorefresh.append(targetedit)

    def RemoveFunc(self,topitemID, parentitemID):
        if(topitemID not in self.topItemsDict.keys()):
            return False # 该父项在顶级列表中不存在
        elif(parentitemID not in self.topItemsDict[topitemID][1].keys()):
            return False # 该父项在二级列表中不存在
        
        parent_item = self.topItemsDict[topitemID][0]
        child_item = self.topItemsDict[topitemID][1][parentitemID][0]
        parent_item.removeChild(child_item)
        self.topItemsDict[topitemID][1].pop(parentitemID)  # [parentitemID][0]
        return True

