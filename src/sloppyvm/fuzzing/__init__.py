"""Fuzzing framework for SloppyVM."""

from .fuzzer import (
    ExecutionResult, Success, ExceptionThrown, Crash,
    FuzzingStatistics,
    run_fuzzer,
)

from .expression import (
    Expr, Const, Add, Mul, Byte,
    UINT32_MAX,
    compile_expr_to_instructions,
    compile_expr,
    random_expr,
)
