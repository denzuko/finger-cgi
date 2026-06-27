package finger_cgi.slsa

import rego.v1

deny contains msg if {
    input.event_name == "release"
    not input.slsa_provenance_attached
    msg := "SLSA: release must have provenance attached before upload"
}

deny contains msg if {
    input.event_name == "push"
    input.ref == "refs/heads/main"
    not input.provenance_workflow_triggered
    msg := "SLSA: push to main must trigger provenance generation workflow"
}

deny contains msg if {
    input.slsa_verifier_exit_code != 0
    msg := sprintf("SLSA: slsa-verifier failed with exit code %d",
                   [input.slsa_verifier_exit_code])
}
