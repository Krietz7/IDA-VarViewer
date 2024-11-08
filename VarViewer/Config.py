# [loaded size]
STACK_SIZE_ABOVE = 30
STACK_SIZE_BELOW = 60

STACK_SIZE_ABOVE_MAX = 40
STACK_SIZE_BELOW_MAX = 100

STACK_SIZE_ABOVE_MIN = 0
STACK_SIZE_BELOW_MIN = 40

ONCE_LOAD_SIZE = 2
INPUT_MAX_STACK_SIZE = 300

# [setting]
VARIABLE_VIEW_HOTKEY = "Shift-Ctrl-V"
STACK_VIEW_HOTKEY = "Shift-Ctrl-S"


'''
Whether to check function flags before tracing its stack frame base address 

If True, the function will check function flags before tracing its stack frame base address and
avoid trace the function stack frame which not meeting requirements
to ensure that the computed stack variables address is correct

If False, the function will not check function flags before tracing its stack frame base address.
This may result in calculated a wrong stack variables address
'''
CHECK_FUNC_FLAG_BEFORE_TRACE= False


# [define color]
DEFINE_LINE_COLOR = "#000000"
TRANSPARENT = "#00FFFFFF"

# [viewer title]
STACK_WIDGET_TITLE = "Stack View"
WIDGET_TITLE = "Viewer"

# [text font]
TEXT_FONT = "Consolas"
TEXT_FONT_SIZE = 10

DEFINE_BACKGROUND_COLOR = "#FFFFFF"
SELECT_LINE_BACKGROUND_COLOR = "#80AAAAAA"


# [StackContainer]
DEBUG_BACKGROUND_COLOR =  "#CCFFFF"    # (debug) Line background = Default

DEBUG_BACKGROUND_ROW_COLOR1 =  "#CCFFFF"
DEBUG_BACKGROUND_ROW_COLOR2 =  "#CCFBFF"

QHEADER_BACKGROUND_COLOR = "#F3F3F3"
QHEADER_BACKGROUND_COLOR_HOVER = "#EDEDED"

TEXT_SELECTED_COLOR = "#FFFFFF"
TEXT_SELECTED_BACKGROUND_COLOR = "#C0BBAF"  # Line background = Selected

STACK_POINTS_REGS_COLOR = "#4040FF"
STACK_ADDRESS_COLOR = "#808000"

# [variables container]
DEBUG_BACKGROUND_LINE_COLOR1 =  "#CCFFFF"
DEBUG_BACKGROUND_LINE_COLOR2 =  "#CCFBFF"
SELECTED_ITEM_BACKGROUND_COLOR = "#8ED4FA"

TOP_ITEM_COLOR = "#000080"
FUNCTION_ITEM_COLOR = "#004080"

VAR_NAME_COLOR = "#4040C0"
STKVAR_NAME_COLOR = "#4040C0"
REGVAR_NAME_COLOR = "#4080C0"

VAR_TYPE_COLOR = "#8080B0"
VAR_VALUE_COLOR = "#004080"
VAR_REMARK_COLOR = "4040FF"
VAR_ADDR_COLOR = "#8080FF"

# [remark]
STACK_VARIBLE_REMARK_COLOR = "#4040FF"
STACK_BASE_REMARK_COLOR = "#408080"
STACK_RETURN_REMARK_COLOR = "#408080"

# [description]
T_VALUE_SEG_COLOR = "#000080"  # Dummy Data Name
T_CODE_SEG_COLOR = "#FF0000"   # Code reference to tail byte
T_DATA_SEG_COLOR = "#FF00FF"   # Line prefix: External mane definition segment
T_STACK_SEG_COLOR = "#808000"  # Line prefix: Unexplored byte
T_BSS_SEG_COLOR = "#808080"    # Line prefix: Data bytes
T_CONST_SEG_COLOR = "#747D8C"  # Line prefix: Single instruction

T_CODE_COLOR = "#000080" # Instruction
T_DATA_COLOR = "#008040" # Numeric constant
T_STACK_VAR_COLOR = "#8040FF"



ARROW_SYMBOL = "->"
ARROW_SYMBOL_COLOR = "#0000FF" # Default
