# A tiny stack Crosswind can scan without a cloud account.
#
# Used by CI to exercise the composite action end to end, and useful locally
# to see what a real scan does:
#
#     cd examples/stacks
#     tofu init && tofu apply -auto-approve
#     echo "changed by hand" > out/notes.txt
#     crosswind scan --path . --no-attribution
#
# The `local` provider reports a modified file as deleted rather than
# updated, because its Read compares a checksum and drops the resource from
# state on a mismatch. That is real drift, and it is why the end-to-end
# tests assert a `deleted` kind for an edited file.

terraform {
  required_version = ">= 1.5"
  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

resource "local_file" "notes" {
  filename = "${path.module}/out/notes.txt"
  content  = "managed by Terraform\n"
}

resource "local_file" "config" {
  filename = "${path.module}/out/config.json"
  content  = jsonencode({ mode = "strict", replicas = 2 })
}
