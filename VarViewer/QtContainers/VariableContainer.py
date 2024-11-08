from PyQt5.QtWidgets import QWidget,QTreeWidget,QMenu,\
                            QAction,QTreeWidgetItem,QVBoxLayout

from VarViewer.config import *
from VarViewer.QtContainers.ReadOnlyLineEdit import ReadOnlyLineEdit
from VarViewer.QtContainers.TemporaryTextEdit import TemporaryItemViewer,TemporaryTextEdit

class VariableContainer(QWidget):
    '''
    a container to display variables information by tree structure
    these variables are grouped by the function they are in

    Tree Viewer
    ├── Top_item1
    |       ├── Func1
    |       |     ├── Var1
    |       |     └── Var2
    |       └── Func2
    |             ├── Var1
    |             └── Var2
    └── Top_item2
        ...

    '''
    def __init__(self, parent,parent_viewer):
        super().__init__(parent)
        self.parent = parent_viewer

        self.tree_widget = QTreeWidget(self)
        self.tree_widget.setIndentation(15)
        self.tree_widget.setUniformRowHeights(True)

        # Set the header
        self.tree_widget.setHeaderHidden(False)
        self.tree_widget.setColumnCount(4)
        self.tree_widget.setHeaderLabels(['Name', 'Type', 'Value','Address', ])

        self.tree_widget.setColumnWidth(0, 400)
        self.tree_widget.setColumnWidth(1, 250)
        self.tree_widget.setColumnWidth(2, 300)
        self.tree_widget.setColumnWidth(3, 450)

        # Private properties
        self._items_dict = {}  # item_id : [item, [child_item_id]]
        self._vars_dict = {} # var_id : var_item
        self._wait_to_refresh = []

        self.backgroundcolor = DEFINE_BACKGROUND_COLOR
        self.backgroundcolor2 = DEFINE_BACKGROUND_COLOR

        self.init_tree()
        # Setting up the layout
        layout = QVBoxLayout()
        layout.addWidget(self.tree_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

    def init_tree(self):
        self.reset_QSS()
        self.tree_widget.setAlternatingRowColors(True)
        self.add_top_level_item("lvar","Local variables",TOP_ITEM_COLOR)
        self.add_top_level_item("gvar","Global variables",TOP_ITEM_COLOR)

    def reset_QSS(self):
        QSS_STR = f"""
            QTreeWidget {{
                alternate-background-color: {self.backgroundcolor2};
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
            """
        self.tree_widget.setStyleSheet(QSS_STR)


    def contextMenuEvent(self, event):
        self.show_context_menu(self.mapToGlobal(event.pos()))


    # Refresh when the widegt is displayed
    def showEvent(self, event):
        if hasattr(self.parent,"RefreshVariableContainer"):
            self.parent.RefreshVariableContainer()
            self.refresh_window()
            super().showEvent(event)

    def show_context_menu(self, pos, item = None):
        menu = QMenu(self)

        action1 = QAction('expamd all nodes', self)
        action2 = QAction('fold all nodes', self)
        action3 = QAction('Reinitialize the window', self)
        action4 = QAction('Show the item', self)
        action5 = QAction('Reset pointer size', self)
        action6 = QAction('Add global var', self)

        action1.triggered.connect(lambda: self.expand_all_nodes(pos))
        action2.triggered.connect(lambda: self.fold_all_nodes(pos))
        action3.triggered.connect(self.reinitialize_window)
        action4.triggered.connect(lambda: self.show_the_item(item))
        action5.triggered.connect(lambda: self.reset_pointer_size(item))
        action6.triggered.connect(self.add_global_var)

        if item is None:
            action4.setVisible(False)
            action5.setVisible(False)

        menu.addAction(action1)
        menu.addAction(action2)
        menu.addSeparator()
        menu.addAction(action3)
        menu.addSeparator()
        menu.addAction(action4)
        menu.addAction(action5)
        menu.addAction(action6)

        menu.exec_(pos)

    def reinitialize_window(self):
        self._items_dict.clear()
        self._vars_dict.clear()
        self._wait_to_refresh.clear()
        self.tree_widget.clear()
        self.add_top_level_item("lvar","Local variables",TOP_ITEM_COLOR)
        self.add_top_level_item("gvar","Global variables",TOP_ITEM_COLOR)
        if hasattr(self.parent,"InitVariableContainer"):
            self.parent.InitVariableContainer()


    def expand_all_nodes(self,pos = None):
        def expand_recursively(item):
            item.setExpanded(True)
            for i in range(item.childCount()):
                child = item.child(i)
                expand_recursively(child)

        if pos is not None:
            item = self.tree_widget.itemAt(pos)
            if item:
                selected_items = self.tree_widget.selectedItems()
                for item in selected_items:
                    expand_recursively(item)
                return

        # Unselected item, expand all nodes
        for i in range(self.tree_widget.topLevelItemCount()):
            top_level_item = self.tree_widget.topLevelItem(i)
            expand_recursively(top_level_item)

    def fold_all_nodes(self,pos = None):
        def fold_recursively(item):
            item.setExpanded(False)
            for i in range(item.childCount()):
                child = item.child(i)
                fold_recursively(child)
        item = self.tree_widget.itemAt(pos)

        if pos is not None:
            item = self.tree_widget.itemAt(pos)
            if item:
                selected_items = self.tree_widget.selectedItems()
                for item in selected_items:
                    fold_recursively(item)
                return

        # Unselected item, fold all nodes
        for i in range(self.tree_widget.topLevelItemCount()):
            top_level_item = self.tree_widget.topLevelItem(i)
            fold_recursively(top_level_item)

    def show_the_item(self,item):
        if isinstance(item,ReadOnlyLineEdit):
            tmp_text_edit = TemporaryTextEdit(None,self,self.backgroundcolor,item.line_color)
            text = item.text()
            tmp_text_edit.setPlainText(text)

            itemviewer = TemporaryItemViewer(self,tmp_text_edit)
            itemviewer.show()

    def reset_pointer_size(self,item):
        if(isinstance(item,ReadOnlyLineEdit) and hasattr(self.parent,"reset_pointer_size")):
            self.parent.reset_pointer_size(item.line_id)

    def add_global_var(self):
        if hasattr(self.parent,"add_global_var"):
            self.parent.add_global_var()

    def refresh_window(self):
        for edit in self._wait_to_refresh:
            edit.refresh()
        self._wait_to_refresh.clear()
        self.tree_widget.setColumnWidth(0, 299)
        self.tree_widget.setColumnWidth(0, 300)

    def expand_node(self, itemID):
        if itemID in self._items_dict:
            item = self._items_dict[itemID][0]
            item.setExpanded(True)


    # itemID: Unique identifier of the item within the items list
    def add_top_level_item(self,itemID,itemName,color=None):
        if (itemID in self._items_dict or itemName is None):
            return False

        item = QTreeWidgetItem()
        self.tree_widget.addTopLevelItem(item)

        item_edit = ReadOnlyLineEdit(itemName,self)
        item_edit.set_bgcolor(TRANSPARENT)
        if color is not None:
            item_edit.set_color(color)

        self.tree_widget.setItemWidget(item, 0, item_edit)

        self._items_dict[itemID] = [item,[]]
        self._wait_to_refresh.append(item_edit)
        return True

    def add_func_item(self,parentitemID,itemID,itemName,color=None):
        if (parentitemID not in self._items_dict or\
                itemID in self._items_dict or itemName is None):
            return False

        parentitem = self._items_dict[parentitemID][0]
        item = QTreeWidgetItem()
        parentitem.insertChild(0,item)

        item_edit = ReadOnlyLineEdit(itemName,self)
        item_edit.set_bgcolor(TRANSPARENT)
        if color is not None:
            item_edit.set_color(color)

        self.tree_widget.setItemWidget(item, 0, item_edit)

        # Add own id to the sub-item_id list of the parent item
        self._items_dict[parentitemID][1].append(itemID)
        self._items_dict[itemID] = [item,[]]


        self._wait_to_refresh.append(item_edit)
        return True


    def add_variable_item(self, parentitemID,VarID, Varname, \
                          Type=None, value=None, Address=None, Color=None):
        if (parentitemID not in self._items_dict or
                VarID in self._items_dict[parentitemID][1] or
                Varname is None):
            return False

        parentitem = self._items_dict[parentitemID][0]
        item = QTreeWidgetItem()
        parentitem.addChild(item)

        Editlist = [ReadOnlyLineEdit(Varname,self,VarID),ReadOnlyLineEdit(Type,self,VarID),\
                    ReadOnlyLineEdit(value,self,VarID),ReadOnlyLineEdit(Address,self,VarID)]
        ColorList = [VAR_NAME_COLOR,VAR_TYPE_COLOR,VAR_VALUE_COLOR,VAR_ADDR_COLOR]
        if Color is not None:
            ColorList[0] = Color
        self._wait_to_refresh += Editlist

        for i in range(self.tree_widget.columnCount()):
            edit = Editlist[i]
            color = ColorList[i]

            edit.set_bgcolor(TRANSPARENT)
            edit.set_color(color)
            edit.refresh()
            self.tree_widget.setItemWidget(item, i, edit)

        self._items_dict[parentitemID][1].append(VarID)
        self._items_dict[VarID] = [item,[]]
        self._vars_dict[VarID] = item
        return True

    def add_varible_member(self,VarID,memberID,memberName,\
                           Type=None, value=None, Address=None, Color=None):
        if (VarID not in self._vars_dict or memberID in self._vars_dict or memberName is None):
            return False

        targetedit = self._vars_dict[VarID]
        item = QTreeWidgetItem()
        targetedit.addChild(item)

        Editlist = [ReadOnlyLineEdit(memberName,self,VarID),ReadOnlyLineEdit(Type,self,VarID),\
                    ReadOnlyLineEdit(value,self,VarID),ReadOnlyLineEdit(Address,self,VarID)]
        ColorList = [VAR_NAME_COLOR,VAR_TYPE_COLOR,VAR_VALUE_COLOR,VAR_ADDR_COLOR]
        if Color is not None:
            ColorList[0] = Color
        self._wait_to_refresh += Editlist

        for i in range(self.tree_widget.columnCount()):
            edit = Editlist[i]
            color = ColorList[i]

            edit.set_bgcolor(TRANSPARENT)
            edit.set_color(color)
            edit.refresh()
            self.tree_widget.setItemWidget(item, i, edit)

        self._vars_dict[memberID] = item
        return True

    def del_varible_members(self,VarID):
        if VarID not in self._vars_dict:
            return False
        targetedit = self._vars_dict[VarID]
        while targetedit.childCount() > 0:
            targetedit.removeChild(targetedit.child(0))
        return True

    def EditVaribleInfo(self, VarID, Text, column, color=None):
        if (VarID not in self._vars_dict or Text is None or column is None):
            return False

        targetedit =  self.tree_widget.itemWidget(self._vars_dict[VarID], column)

        targetedit.edit_line(Text,color)
        targetedit.refresh()
        self._wait_to_refresh.append(targetedit)
        return True

    def InsertVaribleInfo(self, VarID, Text, column, color=None):
        if (VarID not in self._vars_dict or Text is None or column is None):
            return False

        targetedit =  self.tree_widget.itemWidget(self._vars_dict[VarID], column)

        targetedit.insert_text(Text,color)
        targetedit.refresh()
        self._wait_to_refresh.append(targetedit)
        return True

    def RemoveItem(self,parentitemID,ItemID):
        if(ItemID not in self._items_dict or parentitemID not in self._items_dict):
            return False

        parentitem = self._items_dict[parentitemID][0]
        item = self._items_dict[ItemID][0]

        childitems_id = self._items_dict[ItemID][1]
        for childitem_id in childitems_id:
            self.RemoveItem(ItemID,childitem_id)

        parentitem.removeChild(item)
        del self._items_dict[ItemID]
        self._items_dict[parentitemID][1].remove(ItemID)
        return True

    def widget_double_click(self,selected_data):
        if hasattr(self.parent,"widget_double_click"):
            self.parent.widget_double_click(selected_data)
