"""SloppyVM: A 64-bit stack-based virtual machine for testing research."""

from .spec import (
    # Constants
    UINT64_MAX,
    OP_PUSH4, OP_ADD, OP_MUL, OP_BYTE,
    # Instructions
    PUSH4, ADD, MUL, BYTE, Instruction,
    # Exceptions
    SloppyVMException, InvalidInstruction, StackUnderflow,
    # Serialization
    serialize_instruction, serialize_program,
    deserialize_instruction, deserialize_program,
    # VM State & Execution
    VMState, execute, execute_program, execute_bytecode,
)

from .registry import (
    get_available_versions,
    get_implementation,
)

# Expression API re-exported from fuzzing module
from .fuzzing.expression import (
    Expr, Const, Add, Mul, Byte,
    UINT32_MAX,
    compile_expr_to_instructions,
    compile_expr,
    random_expr,
)

__version__ = "0.1.0"
