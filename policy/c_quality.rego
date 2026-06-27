package finger_cgi.c_quality

import rego.v1

blocked_rules := {
    "clang-analyzer-core.NullDereference",
    "clang-analyzer-unix.Malloc",
    "clang-analyzer-security.insecureAPI.strcpy",
    "clang-analyzer-security.insecureAPI.gets",
    "bufferAccessOutOfBounds",
    "outOfBounds",
    "doubleFree",
    "useAfterFree",
    "uninitvar",
}

blocked_levels       := {"error"}
cvss_block_threshold := 7.0

violations contains msg if {
    run    := input.runs[_]
    result := run.results[_]
    result.ruleId in blocked_rules
    loc    := result.locations[0].physicalLocation
    msg := sprintf("BLOCKED rule %v in %v:%v — %v",
        [result.ruleId, loc.artifactLocation.uri,
         loc.region.startLine, result.message.text])
}

violations contains msg if {
    run    := input.runs[_]
    result := run.results[_]
    result.level in blocked_levels
    not result.ruleId in blocked_rules
    loc    := result.locations[0].physicalLocation
    msg := sprintf("ERROR level finding: %v in %v:%v — %v",
        [result.ruleId, loc.artifactLocation.uri,
         loc.region.startLine, result.message.text])
}

required_matrix_prefixes := {
    "net.matrix.organization=",
    "net.matrix.orgunit=",
    "net.matrix.owner=",
    "net.matrix.oid=",
    "net.matrix.application=",
    "net.matrix.role=",
    "net.matrix.version=",
}

binary_has_prefix(prefix) if {
    some s in input.binary_strings
    startswith(s, prefix)
}

violations contains msg if {
    some prefix in required_matrix_prefixes
    not binary_has_prefix(prefix)
    msg := sprintf("binary missing net.matrix attribution string: %v", [prefix])
}

violation_count := count(violations)
summary := {"pass": count(violations) == 0, "violation_count": count(violations), "violations": violations}
