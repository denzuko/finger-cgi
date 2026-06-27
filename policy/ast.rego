package finger_cgi.ast

import rego.v1

# ── Rule 1: No forbidden function calls ──────────────────────────────────── #
# Input: ast_calls array from clang -ast-dump=json | jq extraction

forbidden_calls := {"system", "popen", "execl", "execv", "execvp", "execve"}

violations contains msg if {
    some call in input.ast_calls
    call.callee in forbidden_calls
    msg := sprintf("forbidden call: %v at %v:%v",
        [call.callee, call.file, call.line])
}

# ── Rule 2: String comparison must not use == on char* ───────────────────── #

violations contains msg if {
    some call in input.ast_calls
    call.callee == "strcmp"
    call.result_unchecked == true
    msg := sprintf("unchecked strcmp result at %v:%v",
        [call.file, call.line])
}

# ── Rule 3: Coverage gate (90%%) ─────────────────────────────────────────── #
# Input: test_count (int), function_count (int)

violations contains msg if {
    input.function_count > 0
    coverage := (input.test_count * 100) / input.function_count
    coverage < 90
    msg := sprintf("coverage %v%% below 90%% threshold (%v tests / %v functions)",
        [coverage, input.test_count, input.function_count])
}

# ── Summary ───────────────────────────────────────────────────────────────── #

summary := {
    "pass":            count(violations) == 0,
    "violation_count": count(violations),
    "violations":      violations,
}
