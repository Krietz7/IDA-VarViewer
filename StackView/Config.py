import configparser
import os
from ast import literal_eval

config = configparser.ConfigParser()
config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'Config.ini'))

def get_config_value(section, option, default):
    result = config.get(section, option, fallback=default)
    return result if result != "" else default

# 设置默认值
default_values = {
    # widge title
    'STACK_WIDGET_TITLE' : "Stack View",
    'WIDGET_TITLE' : "Viewer",

    # text font
    'TEXT_FONT' : "Consolas",
    'TEXT_FONT_SIZE' : "10",


    # loaded size
    'STACK_SIZE_ABOVE' : "30",
    'STACK_SIZE_BELOW' : "60",

    'STACK_SIZE_ABOVE_MAX' : "40",
    'STACK_SIZE_BELOW_MAX' : "100",

    'STACK_SIZE_ABOVE_MIN' : "0",
    'STACK_SIZE_BELOW_MIN' : "40",

    'ONCE_LOAD_SIZE' : "3",



    # define color
    'DEFINE_LINE_COLOR' : "#000000",
    'TRANSPARENT' : "#00FFFFFF",


    'DEFINE_BACKGROUND_COLOR' : "#FFFFFF",
    'SELECT_LINE_BACKGROUND_COLOR' : "#80AAAAAA",


    # StackContainer:
    'DEBUG_BACKGROUND_COLOR' :  "#CCFFFF",    #IDA: (debug) Line background :Default

    'DEBUG_BACKGROUND_ROW_COLOR1' :  "#CCFFFF",
    'DEBUG_BACKGROUND_ROW_COLOR2' :  "#CCFBFF",

    'QHEADER_BACKGROUND_COLOR' : "#F3F3F3",
    'QHEADER_BACKGROUND_COLOR_HOVER' : "#EDEDED",

    'TEXT_SELECTED_COLOR' : "#FFFFFF",
    'TEXT_SELECTED_BACKGROUND_COLOR' : "#c0bbaf",  # Line background: Selected

    'STACK_POINTS_REGS_COLOR' : "#4040FF",   # 
    'STACK_ADDRESS_COLOR' : "#808000",

    # variables container
    'DEBUG_BACKGROUND_LINE_COLOR1' :  "#CCFFFF",
    'DEBUG_BACKGROUND_LINE_COLOR2' :  "#CCFBFF",
    'SELECTED_ITEM_BACKGROUND_COLOR' : "#8ed4fa",

    'TOP_ITEM_COLOR' : "#2f3542",
    'FUNCTION_ITEM_COLOR' : "#1b1464",

    'VAR_NAME_COLOR' : "#8e44ad",
    'STKVAR_NAME_COLOR' : "#8e44ad",
    'REGVAR_NAME_COLOR' : "#5352ed",

    'VAR_TYPE_COLOR' : "#00b894",
    'VAR_VALUE_COLOR' : "#6c5ce7",
    'VAR_REMARK_COLOR' : "#2f3542",
    'VAR_ADDR_COLOR' : "#341f97",

    # remark
    'STACK_VARIBLE_REMARK_COLOR' : "#4040ff",
    'STACK_BASE_REMARK_COLOR' : "#408080",
    'STACK_RETURN_REMARK_COLOR' : "#408080",

    # description
    'MAX_DATA_DISPLAY_SIZE' : "24",
    'T_VALUE_SEG_COLOR' : "#000080",  # Dummy Data Name
    'T_CODE_SEG_COLOR' : "#ff0000",   # Code reference to tail byte
    'T_DATA_SEG_COLOR' : "#ff00ff",   # Line prefix: External mane definition segment
    'T_STACK_SEG_COLOR' : "#808000",  # Line prefix: Unexplored byte
    'T_BSS_SEG_COLOR' : "#808080",    # Line prefix: Data bytes
    'T_CONST_SEG_COLOR' : "#747d8c",  # Line prefix: Single instruction

    'T_CODE_COLOR' : "#000080", # Instruction
    'T_DATA_COLOR' : "#008040", # Numeric constant
    'T_STACK_VAR_COLOR' : "#8040ff", 



    'ARROW_SYMBOL' : "->",
    'ARROW_SYMBOL_COLOR' : "#0000ff", # Default

    # setting
    'ANALYTICS_FUZZY_SP': "False"
}



# [widge title] 
STACK_WIDGET_TITLE = get_config_value('widge title', 'STACK_WIDGET_TITLE', default_values['WIDGET_TITLE'])
WIDGET_TITLE = get_config_value('widge title', 'WIDGET_TITLE', default_values['WIDGET_TITLE'])

# [text font] 
TEXT_FONT = get_config_value('text font', 'TEXT_FONT', default_values['TEXT_FONT'])
TEXT_FONT_SIZE = int(get_config_value('text font', 'TEXT_FONT_SIZE', default_values['TEXT_FONT_SIZE']))

# [loaded size] 
STACK_SIZE_ABOVE = int(get_config_value('loaded size', 'STACK_SIZE_ABOVE', default_values['STACK_SIZE_ABOVE']))
STACK_SIZE_BELOW = int(get_config_value('loaded size', 'STACK_SIZE_BELOW', default_values['STACK_SIZE_BELOW']))
STACK_SIZE_ABOVE_MAX = int(get_config_value('loaded size', 'STACK_SIZE_ABOVE_MAX', default_values['STACK_SIZE_ABOVE_MAX']))
STACK_SIZE_BELOW_MAX = int(get_config_value('loaded size', 'STACK_SIZE_BELOW_MAX', default_values['STACK_SIZE_BELOW_MAX']))
STACK_SIZE_ABOVE_MIN = int(get_config_value('loaded size', 'STACK_SIZE_ABOVE_MIN', default_values['STACK_SIZE_ABOVE_MIN']))
STACK_SIZE_BELOW_MIN = int(get_config_value('loaded size', 'STACK_SIZE_BELOW_MIN', default_values['STACK_SIZE_BELOW_MIN']))
ONCE_LOAD_SIZE = int(get_config_value('loaded size', 'ONCE_LOAD_SIZE', default_values['ONCE_LOAD_SIZE']))

# [define color]
DEFINE_LINE_COLOR = get_config_value('define color', 'DEFINE_LINE_COLOR', default_values['DEFINE_LINE_COLOR'])
TRANSPARENT = get_config_value('define color', 'TRANSPARENT', default_values['TRANSPARENT'])
DEFINE_BACKGROUND_COLOR = get_config_value('define color', 'DEFINE_BACKGROUND_COLOR', default_values['DEFINE_BACKGROUND_COLOR'])
SELECT_LINE_BACKGROUND_COLOR = get_config_value('define color', 'SELECT_LINE_BACKGROUND_COLOR', default_values['SELECT_LINE_BACKGROUND_COLOR'])

# [StackContainer]
DEBUG_BACKGROUND_COLOR = get_config_value('StackContainer', 'DEBUG_BACKGROUND_COLOR', default_values['DEBUG_BACKGROUND_COLOR'])
DEBUG_BACKGROUND_ROW_COLOR1 = get_config_value('StackContainer', 'DEBUG_BACKGROUND_ROW_COLOR1', default_values['DEBUG_BACKGROUND_ROW_COLOR1'])
DEBUG_BACKGROUND_ROW_COLOR2 = get_config_value('StackContainer', 'DEBUG_BACKGROUND_ROW_COLOR2', default_values['DEBUG_BACKGROUND_ROW_COLOR2'])
QHEADER_BACKGROUND_COLOR = get_config_value('StackContainer', 'QHEADER_BACKGROUND_COLOR', default_values['QHEADER_BACKGROUND_COLOR'])
QHEADER_BACKGROUND_COLOR_HOVER = get_config_value('StackContainer', 'QHEADER_BACKGROUND_COLOR_HOVER', default_values['QHEADER_BACKGROUND_COLOR_HOVER'])
TEXT_SELECTED_COLOR = get_config_value('StackContainer', 'TEXT_SELECTED_COLOR', default_values['TEXT_SELECTED_COLOR'])
TEXT_SELECTED_BACKGROUND_COLOR = get_config_value('StackContainer', 'TEXT_SELECTED_BACKGROUND_COLOR', default_values['TEXT_SELECTED_BACKGROUND_COLOR'])
STACK_POINTS_REGS_COLOR = get_config_value('StackContainer', 'STACK_POINTS_REGS_COLOR', default_values['STACK_POINTS_REGS_COLOR'])
STACK_ADDRESS_COLOR = get_config_value('StackContainer', 'STACK_ADDRESS_COLOR', default_values['STACK_ADDRESS_COLOR'])

# [VariablesContainer]
DEBUG_BACKGROUND_LINE_COLOR1 = get_config_value('StackContainer', 'DEBUG_BACKGROUND_LINE_COLOR1', default_values['DEBUG_BACKGROUND_LINE_COLOR1'])
DEBUG_BACKGROUND_LINE_COLOR2 = get_config_value('StackContainer', 'DEBUG_BACKGROUND_LINE_COLOR2', default_values['DEBUG_BACKGROUND_LINE_COLOR2'])
SELECTED_ITEM_BACKGROUND_COLOR = get_config_value('StackContainer', 'SELECTED_ITEM_BACKGROUND_COLOR', default_values['SELECTED_ITEM_BACKGROUND_COLOR'])
TOP_ITEM_COLOR = get_config_value('StackContainer', 'TOP_ITEM_COLOR', default_values['TOP_ITEM_COLOR'])
FUNCTION_ITEM_COLOR = get_config_value('StackContainer', 'FUNCTION_ITEM_COLOR', default_values['FUNCTION_ITEM_COLOR'])
VAR_NAME_COLOR = get_config_value('StackContainer', 'VAR_NAME_COLOR', default_values['VAR_NAME_COLOR'])
STKVAR_NAME_COLOR = get_config_value('StackContainer', 'STKVAR_NAME_COLOR', default_values['STKVAR_NAME_COLOR'])
REGVAR_NAME_COLOR = get_config_value('StackContainer', 'REGVAR_NAME_COLOR', default_values['REGVAR_NAME_COLOR'])
VAR_TYPE_COLOR = get_config_value('StackContainer', 'VAR_TYPE_COLOR', default_values['VAR_TYPE_COLOR'])
VAR_VALUE_COLOR = get_config_value('StackContainer', 'VAR_VALUE_COLOR', default_values['VAR_VALUE_COLOR'])
VAR_REMARK_COLOR = get_config_value('StackContainer', 'VAR_REMARK_COLOR', default_values['VAR_REMARK_COLOR'])
VAR_ADDR_COLOR = get_config_value('StackContainer', 'VAR_ADDR_COLOR', default_values['VAR_ADDR_COLOR'])

# [Remark]
STACK_VARIBLE_REMARK_COLOR = get_config_value('Remark', 'STACK_VARIBLE_REMARK_COLOR', default_values['STACK_VARIBLE_REMARK_COLOR'])
STACK_VARIBLE_REMARK_COLOR = get_config_value('Remark', 'STACK_VARIBLE_REMARK_COLOR', default_values['STACK_VARIBLE_REMARK_COLOR'])
STACK_RETURN_REMARK_COLOR = get_config_value('Remark', 'STACK_RETURN_REMARK_COLOR', default_values['STACK_RETURN_REMARK_COLOR'])

# [Description]

MAX_DATA_DISPLAY_SIZE = int(get_config_value('Description', 'MAX_DATA_DISPLAY_SIZE', default_values['MAX_DATA_DISPLAY_SIZE']))
T_VALUE_SEG_COLOR = get_config_value('Description', 'T_VALUE_SEG_COLOR', default_values['T_VALUE_SEG_COLOR'])
T_CODE_SEG_COLOR = get_config_value('Description', 'T_CODE_SEG_COLOR', default_values['T_CODE_SEG_COLOR'])
T_DATA_SEG_COLOR = get_config_value('Description', 'T_DATA_SEG_COLOR', default_values['T_DATA_SEG_COLOR'])
T_STACK_SEG_COLOR = get_config_value('Description', 'T_STACK_SEG_COLOR', default_values['T_STACK_SEG_COLOR'])
T_BSS_SEG_COLOR = get_config_value('Description', 'T_BSS_SEG_COLOR', default_values['T_BSS_SEG_COLOR'])
T_CONST_SEG_COLOR = get_config_value('Description', 'T_CONST_SEG_COLOR', default_values['T_CONST_SEG_COLOR'])
T_CODE_COLOR = get_config_value('Description', 'T_CODE_COLOR', default_values['T_CODE_COLOR'])
T_DATA_COLOR = get_config_value('Description', 'T_DATA_COLOR', default_values['T_DATA_COLOR'])
T_STACK_VAR_COLOR =  get_config_value('Description', 'T_STACK_VAR_COLOR', default_values['T_STACK_VAR_COLOR'])
ARROW_SYMBOL = get_config_value('Description', 'ARROW_SYMBOL', default_values['ARROW_SYMBOL'])
ARROW_SYMBOL_COLOR = get_config_value('Description', 'ARROW_SYMBOL_COLOR', default_values['ARROW_SYMBOL_COLOR'])

# setting
ANALYTICS_FUZZY_SP = literal_eval(get_config_value('setting', 'ANALYTICS_FUZZY_SP', default_values['ANALYTICS_FUZZY_SP']))










































