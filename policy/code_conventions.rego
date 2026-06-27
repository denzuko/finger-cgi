package finger_cgi.code_conventions

import rego.v1

# Forbidden function calls — enforced via clang AST dump.
# Input: ast_calls.json produced by clang -ast-dump=json | jq

forbidden_calls := {"system", "popen", "execl", "execv", "execvp", "execve"}

violations contains msg if {
    some call in input.calls
    call.callee in forbidden_calls
    msg := sprintf("forbidden call: %v at %v:%v",
        [call.callee, call.file, call.line])
}
