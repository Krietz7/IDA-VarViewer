from PyQt5.QtGui import QPalette,QColor,QBrush
from PyQt5.QtWidgets import QWidget,QHeaderView,QTableWidget,QVBoxLayout,\
    QMenu,QAction,QTableWidgetItem

from VarViewer.config import *
from VarViewer.QtContainers.ReadOnlyLineEdit import ReadOnlyLineEdit
from VarViewer.QtContainers.ReadOnlyTextEdit import ReadOnlyTextEdit
from VarViewer.QtContainers.TemporaryTextEdit import TemporaryItemViewer,TemporaryTextEdit


class StackContainer(QWidget):
    def __init__(self, parent, bitness, parent_viewer):
        super().__init__(parent)

        # Initialize
        self.parent = parent_viewer
        self.bitness = bitness
        self.unit_size = self.bitness // 8

        '''
        Since each address of the stack is unique, 
        this widget uses the address as a unique ID to indicate each row.
        '''
        self._address_id = []   # row -> address
        self._widget_dict = {}   # widget objname -> widget
        self._tmp_widget_dict = {}  # Used when reset the address_id

        self._wait_to_refresh = []   # Widgets that need to be updated
        self._highlighting_items = []   # The currently highlighted widget
        self._highlighting_address = -1   # The currently highlighted row
        # Unhighlight the restored color
        self._current_highlight_row_original_background_color = []

        self.backgroundColor = DEFINE_BACKGROUND_COLOR
        self.cursor_position = 0   # Pointer position

        self.setGeometry(400, 400, 800, 600)
        self.table_widget = QTableWidget()

        # Header: [Pointer | Address | Value | Description | Remark]
        headers = ["", "Address", "Value","Description", "Remark"]
        self.table_widget.setColumnCount(len(headers))
        self._header_format_dict = {
            0  : "pointer_{:X}",
            1  : "address_{:X}",
            2  : "value_{:X}",
            3  : "description_{:X}",
            4  : "remark_{:X}",
        }
        self.table_widget.setHorizontalHeaderLabels(headers)

        horizontalHeader = self.table_widget.horizontalHeader()
        horizontalHeader.setSectionsClickable(False)  # Unselectable
        horizontalHeader.setSectionsMovable(True) # Allow movement
        horizontalHeader.setMaximumHeight(33)
        horizontalHeader.setMinimumSectionSize(50)

        # Pointer Header
        horizontalHeader.resizeSection(0,75)
        horizontalHeader.setSectionResizeMode(0,QHeaderView.Fixed)

        # Address Header
        horizontalHeader.resizeSection(1,bitness*4-bitness//2+5)
        horizontalHeader.setSectionResizeMode(1,QHeaderView.Fixed)

        # Value Header
        horizontalHeader.resizeSection(2,bitness*4-bitness//2+5)
        horizontalHeader.setSectionResizeMode(2,QHeaderView.Fixed)

        # Description Header
        horizontalHeader.resizeSection(3,1000)
        horizontalHeader.setSectionResizeMode(3,QHeaderView.Interactive)

        # Remark Header
        horizontalHeader.resizeSection(4,600)
        horizontalHeader.setSectionResizeMode(4,QHeaderView.Stretch)


        # Set the column header height and hide it
        verticalheader = self.table_widget.verticalHeader()
        verticalheader.setMaximumSectionSize(27)
        verticalheader.setMinimumSectionSize(27)
        verticalheader.setDefaultSectionSize(27)
        verticalheader.setVisible(False)

        # header right-click menu
        horizontalHeader.customContextMenuRequested.connect(self.show_column_menu)

        # Set scroll mode
        self.table_widget.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
        self.table_widget.setVerticalScrollMode(QTableWidget.ScrollPerPixel)

        # Set the selected event: Highlight the selected item, Highlight the selected row
        self.table_widget.itemSelectionChanged.connect(self._highlight_matching_items)
        self.table_widget.itemSelectionChanged.connect(self._highlight_selected_line)

        # Setting the style
        palette = self.table_widget.palette()
        palette.setColor(QPalette.Window, QColor(255, 255, 255))
        self.table_widget.setPalette(palette)
        self.reset_QSS()
        self.table_widget.setShowGrid(False)

        # Create a vertical layout and Add the table to it
        self.hbox = QVBoxLayout()
        self.hbox.setContentsMargins(0, 0, 0, 0)
        self.hbox.addWidget(self.table_widget)
        self.setLayout(self.hbox)


    # Refresh when the widegt is displayed
    def showEvent(self, event):
        if hasattr(self.parent,"RefreshStackContainer"):
            self.parent.RefreshStackContainer()
            self.refresh_window()
            super().showEvent(event)

    def contextMenuEvent(self, event):
        self.show_context_menu(self.mapToGlobal(event.pos()))

    def reset_QSS(self):
        QSS_STR = f"""
            QTableWidget {{
                border: none;  /* Remove the outer border of the table */
                gridline-color: transparent;  /* Remove grid lines between cells */
                background-color: {self.backgroundColor};
            }}
            QHeaderView::section {{    /* Header Elements */
                background-color: {QHEADER_BACKGROUND_COLOR};
                margin:1px;
            }}
            QHeaderView::section:hover{{   /* Hover the pointer over the header element */
                background-color: {QHEADER_BACKGROUND_COLOR_HOVER};
                font-weight: blod;
                border: none;  /* Remove the outer border of the table */

            }}
            QHeaderView::section:checked{{   /* Select the header element */
                margin:0px;
                font-style: normal;
                font-weight: normal;
            }}
            QTableWidget::item:selected{{   /* Select the item element */
                background-color: {SELECT_LINE_BACKGROUND_COLOR};
                border: none;  /* Remove the outer border of the table */
            }}
        """
        self.table_widget.setStyleSheet(QSS_STR)


    # table header right-click menu: Set the column visibility
    def show_column_menu(self, position):
        menu = QMenu(self)

        for col in range(3,self.table_widget.columnCount()):
            action = QAction(self.table_widget.horizontalHeaderItem(col).text(), self)
            action.setCheckable(True)
            action.setChecked(not self.table_widget.isColumnHidden(col))
            action.triggered.connect(lambda checked, c=col: self._toggle_column_visibility(c))
            menu.addAction(action)

        menu.exec_(self.table_widget.horizontalHeader().mapToGlobal(position))

    def _toggle_column_visibility(self, column):
        if self.table_widget.isColumnHidden(column):
            self.table_widget.showColumn(column)
        else:
            self.table_widget.hideColumn(column)


    # table widget right-click menu
    def show_context_menu(self, pos, item = None):
        menu = QMenu(self)

        action1 = QAction('Reinitialize the window', self)
        action2 = QAction('Show The Item', self)
        action3 = QAction('Follow in SP', self)
        action4 = QAction('Follow in BP', self)
        action5 = QAction('Follow in Address', self)
        action6 = QAction('Reset Size', self)

        action1.triggered.connect(self.reinitialize_window)
        action2.triggered.connect(lambda: self.show_the_item(item))
        action3.triggered.connect(self.follow_in_SP)
        action4.triggered.connect(self.follow_in_BP)
        action5.triggered.connect(self.follow_in_address)
        action6.triggered.connect(self.reset_szie)

        if item is None:
            action3.setEnabled(False)

        menu.addAction(action1)
        menu.addSeparator()
        menu.addAction(action2)
        menu.addSeparator()
        menu.addAction(action3)
        menu.addAction(action4)
        menu.addAction(action5)
        menu.addSeparator()
        menu.addAction(action6)

        menu.exec_(pos)

    def refresh_window(self):
        horizontalHeader = self.table_widget.horizontalHeader()
        horizontalHeader.resizeSection(0,76)
        horizontalHeader.resizeSection(0,75)

        for edit in self._wait_to_refresh:
            edit.refresh()
        self._wait_to_refresh.clear()

    def reinitialize_window(self):
        if hasattr(self.parent,"InitStackContainer"):
            self.parent.InitStackContainer()

    def show_the_item(self,item):
        tmp_text_edit = TemporaryTextEdit(None,self,self.backgroundColor,item.line_color)
        if isinstance(item,ReadOnlyTextEdit):
            text = item.toHtml()
            tmp_text_edit.setHtml(text)
        elif isinstance(item,ReadOnlyLineEdit):
            text = item.text()
            tmp_text_edit.setPlainText(text)
        else:
            return False

        itemviewer = TemporaryItemViewer(self,tmp_text_edit)
        itemviewer.show()
        return True

    def follow_in_SP(self):
        self._clear_highlighting_item()
        if hasattr(self.parent,"follow_in_SP"):
            self.parent.follow_in_SP()

    def follow_in_BP(self):
        self._clear_highlighting_item()
        if hasattr(self.parent,"follow_in_BP"):
            self.parent.follow_in_BP()

    def follow_in_address(self):
        select_line = self.table_widget.currentRow()
        select_addr =  self._address_id[select_line]

        self._clear_highlighting_item()
        if hasattr(self.parent,"follow_in_address"):
            self.parent.follow_in_address(select_addr)


    def reset_szie(self):
        self._clear_highlighting_item()
        if hasattr(self.parent,"reset_szie"):
            self.parent.reset_szie()


    def _clear_highlighting_item(self):
        if(self._highlighting_address >= 0 and self._highlighting_address in self._address_id):
            self._change_line_color(self._address_id.index(self._highlighting_address),\
                                   self._current_highlight_row_original_background_color)
            self._current_highlight_row_original_background_color.clear()
            self._highlighting_address = -1

        if self._highlighting_items:
            for items in self._highlighting_items:
                if items[0] in self._widget_dict:
                    item = self._widget_dict[items[0]]
                    item.set_bgcolor(items[1])
                    self._wait_to_refresh.append(item)
            self._highlighting_items.clear()

    def _highlight_matching_items(self):
        if self._highlighting_items:
            for items in self._highlighting_items:
                if items[0] in self._widget_dict:
                    item = self._widget_dict[items[0]]
                    item.set_bgcolor(items[1])
                    self._wait_to_refresh.append(item)
            self._highlighting_items.clear()


        # Get the currently selected cell
        selected_items = self.table_widget.cellWidget(self.table_widget.currentRow(),\
                                                      self.table_widget.currentColumn())
        if selected_items is None:
            return False

        # highlight all cells with the same value in columns 2 and 3
        if selected_items is not None:
            selected_value = selected_items.get_line()
            if selected_value != "":
                for item_objname,item in self._widget_dict.items():
                    if(item.get_line() == selected_value and isinstance(item,ReadOnlyLineEdit)\
                       and (self._header_format_dict[1].replace('{:X}', '') in item_objname\
                       or self._header_format_dict[2].replace('{:X}', '') in item_objname) ):

                        originalcolor = item.get_bgcolor()
                        item.set_bgcolor(0xFFFF33)
                        self._highlighting_items.append([item_objname,originalcolor])
                        self._wait_to_refresh.append(item)

        self.refresh_window()
        return True

    # Change the color of an entire row(colors accepts a single object or an array)
    def _change_line_color(self,line,colors):
        if line >= 0:
            for i in range(self.table_widget.columnCount()):
                if isinstance(colors,list):
                    color = colors[i]
                else:
                    color = colors

                if isinstance(color,str):
                    item = self.table_widget.item(line,i)
                    item.setBackground(QColor(color))
                elif isinstance(color, QBrush) or isinstance(color, QColor):
                    item = self.table_widget.item(line,i)
                    item.setBackground(color)

    def _highlight_selected_line(self):
        if(self._highlighting_address >= 0 and self._highlighting_address in self._address_id):
            self._change_line_color(self._address_id.index(self._highlighting_address),\
                                   self._current_highlight_row_original_background_color)
            self._current_highlight_row_original_background_color.clear()
            self._highlighting_address = -1

        select_line = self.table_widget.currentRow()
        self._highlighting_address = self._address_id[select_line]

        for i in range(self.table_widget.columnCount()):
            item = self.table_widget.item(select_line,i)
            if item is not None:
                brush = item.background().color()
            else:
                brush = TRANSPARENT
            self._current_highlight_row_original_background_color.append(brush)
        self._change_line_color(self._address_id.index(self._highlighting_address),\
                               SELECT_LINE_BACKGROUND_COLOR)

    def _edit_wedget(self, key = None, text = None,color = None):
        if key in self._widget_dict:
            item = self._widget_dict[key]
            item.edit_line(text,color)
            self._wait_to_refresh.append(item)
            return True
        return False

    def _insert_wedget(self, key = None, text = None,color = None):
        if key in self._widget_dict:
            item = self._widget_dict[key]
            item.insert_text(text,color)
            self._wait_to_refresh.append(item)
            return True
        return False

    def _get_wedget_text(self,key = None):
        if key in self._widget_dict:
            item = self._widget_dict[key]
            return item.get_line()
        return False

    def _set_wedget_color(self, key = None, color = None):
        if key in self._widget_dict:
            item = self._widget_dict[key]
            item.set_color(color)
            self._wait_to_refresh.append(item)
            return True
        return False

    def _set_wedget_bgcolor(self, key = None, color = None):
        if key in self._widget_dict:
            item = self._widget_dict[key]
            item.set_bgcolor(color)
            self._wait_to_refresh.append(item)
            return True
        return False

    def _clear_wedget(self, key = None):
        if key in self._widget_dict:
            item = self._widget_dict[key]
            item.clear()
            self._wait_to_refresh.append(item)
            return True
        return False

    def _add_line(self, row, Address, Value, Meaning = None, Description = None):
        if Address in self._address_id or Address < 0:
            return False

        self._address_id.insert(row, Address)
        self.table_widget.insertRow(row)

        format_widths = {8: 16, 4: 8}
        width = format_widths.get(self.unit_size)
        if width is None:
            return False
        address_str = f"{Address:0{width}X}"
        value_str = f"{Value:0{width}X}"

        widgets = [ReadOnlyLineEdit("",self),ReadOnlyLineEdit(address_str,self),\
                   ReadOnlyLineEdit(value_str,self),ReadOnlyTextEdit(Meaning, self),\
                   ReadOnlyLineEdit(Description,self),]

        for i in range(0,self.table_widget.columnCount()):
            # add widgets to table cell
            widget = widgets[i]
            widget_objname = self._header_format_dict[i].format(Address)
            widget.setObjectName(widget_objname)
            self.table_widget.setCellWidget(row,i,widgets[i])

            self._widget_dict[widget_objname] = widget
            self._wait_to_refresh.append(widget)

            # Set alternate backgound colors
            tableItem = QTableWidgetItem()
            if i % 2:
                tableItem.setBackground(QColor(DEBUG_BACKGROUND_ROW_COLOR1))
            else:
                tableItem.setBackground(QColor(DEBUG_BACKGROUND_ROW_COLOR2))
            self.table_widget.setItem(row, i, tableItem)

        return True

    def _delete_line(self, Address):
        if Address not in self._address_id:
            return False
        # Find the row index corresponding to the address and remove it
        row_index = self._address_id.index(Address)
        self.table_widget.removeRow(row_index)
        self._address_id.remove(Address)

        # Remove the widget from the dictionary
        keys_to_remove = [i.format(Address) for i in self._header_format_dict.values()]
        for key in keys_to_remove:
            if key in self._widget_dict:
                del self._widget_dict[key]

        return True

    def add_line_at_begin(self,Address = None,*args):
        if (len(self._address_id) == 0 and Address is None):
            target_addr = -1
        elif len(self._address_id) != 0:
            target_addr = self._address_id[0] - self.bitness // 8
        else:
            target_addr = Address

        if target_addr < 0:
            return False
        return self._add_line(0,target_addr, *args)

    def del_line_at_begin(self):
        if self.table_widget.rowCount() > 0:
            Address = self._address_id[0]
            return self._delete_line(Address)
        return False

    def add_line_at_end(self,Address = None,*args):
        if (len(self._address_id) == 0 and Address is None):
            target_addr = -1
        elif len(self._address_id) != 0:
            target_addr = self._address_id[self.table_widget.rowCount()-1] + self.bitness // 8
        elif Address is not None:
            target_addr = Address
        else:
            return False

        if target_addr < 0:
            return False
        return self._add_line(self.table_widget.rowCount(),target_addr, *args)

    def del_line_at_end(self):
        if self.table_widget.rowCount() > 0:
            Address = self._address_id[self.table_widget.rowCount()-1]
            return self._delete_line(Address)
        return False

    def edit_item(self,Address,Header,text,color = DEFINE_LINE_COLOR):
        if(Address not in self._address_id or Header is None or text is None):
            return False
        key = self._header_format_dict[Header].format(Address)
        if Header == 2:
            if self.unit_size == 8:
                text = f"{text:016X}"
            elif self.unit_size == 4:
                text = f"{text:08X}"
            return self._edit_wedget(key,text,color)
        return self._edit_wedget(key,text,color)

    def insert_text(self,Address,Header,text,color = DEFINE_LINE_COLOR):
        if(Address not in self._address_id or Header is None or text is None):
            return False
        key = self._header_format_dict[Header].format(Address)
        return self._insert_wedget(key,text,color)

    def get_item_text(self,Address,Header):
        if(Address not in self._address_id or Header is None):
            return False
        key = self._header_format_dict[Header].format(Address)
        return self._get_wedget_text(key)

    def change_edit_color(self,Address,Header,Color):
        if(Address not in self._address_id or Header is None):
            return False
        key = self._header_format_dict[Header].format(Address)
        return self._set_wedget_color(key,Color)


    def change_edit_bgcolor(self,Address,Header,Color):
        if(Address not in self._address_id or Header is None):
            return False
        key = self._header_format_dict[Header].format(Address)
        return self._set_wedget_bgcolor(key,Color)

    def clear_item(self,Address,Header):
        if(Address not in self._address_id or Header is None):
            return False
        key = self._header_format_dict[Header].format(Address)
        return self._clear_wedget(key)

    def clear_all_lines(self):
        self.table_widget.setRowCount(0)
        self._address_id.clear()
        self._widget_dict.clear()
        self._wait_to_refresh.clear()
        self._highlighting_items.clear()
        self._highlighting_address = -1

    def roll_to_address(self,Address):
        if Address not in self._address_id:
            return False
        row_index = self._address_id.index(Address)
        self.table_widget.scrollToItem(self.table_widget.item(row_index, 0),\
                                       self.table_widget.PositionAtTop)
        return True

    def get_address_range(self):
        if self._address_id:
            return self._address_id[0], self._address_id[len(self._address_id)-1]
        return None, None

    def enable_updates(self):
        self.table_widget.setUpdatesEnabled(True)

    def disable_updates(self):
        self.table_widget.setUpdatesEnabled(False)

    def widget_double_click(self,selected_data):
        if hasattr(self.parent,"widget_double_click"):
            self.parent.widget_double_click(selected_data)

    def _reset_line_address(self,row,Address):
        if (row < 0 or row >= self.table_widget.rowCount()):
            return False

        for i in range(0,self.table_widget.columnCount()):
            item = self.table_widget.cellWidget(row,i)

            if item is not None:
                new_objname = (self._header_format_dict[i]).format(Address)

                self._tmp_widget_dict[new_objname] = self._widget_dict[item.objectName()]

                item.setObjectName(new_objname)
                item.clear()
                self._wait_to_refresh.append(item)
                if i == 1:
                    if self.unit_size == 8:
                        address_str =  f"{Address:016X}"
                    elif self.unit_size == 4:
                        address_str =  f"{Address:08X}"
                    else:
                        return False
                    item.setText(address_str)
                    item.set_color(STACK_ADDRESS_COLOR)
        return True


    # Reset the address of the entire window
    def reset_address(self,Address,stack_size_above):
        self._clear_highlighting_item()
        self._tmp_widget_dict.clear()
        self._address_id.clear()

        start_address =  Address - stack_size_above * self.bitness // 8
        start_address = max(start_address,0)

        for i in range(self.table_widget.rowCount()):
            self._reset_line_address(i, start_address + i * self.bitness // 8)
            self._address_id.append(start_address + i * self.bitness // 8)
        self._widget_dict =  dict(self._tmp_widget_dict)

        for edit in self._wait_to_refresh:
            edit.refresh()
        self._wait_to_refresh.clear()
        self._highlight_matching_items()
        self._highlight_selected_line()
        return True
