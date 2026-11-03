# Severity rules

Severity decides what a reader looks at first, so the rules live in a data
file you can read and disagree with:
[`src/crosswind/data/severity.yml`](../src/crosswind/data/severity.yml).

**Every finding names the rule that scored it**, in all four output formats.
A severity nobody can trace to a line in a YAML file is a severity nobody
will act on.

## How scoring works

Rules are evaluated **in file order, and the first match wins.**

Not "highest severity wins". A reader who adds a rule at the top expects it
to take effect, and a scoring system where you have to know every other rule
to predict the outcome is one nobody will edit. The shipped file is ordered
most-specific-first for this reason, and `default` is last.

A rule matches when all of these hold:

- the resource `type` matches one of its `types` globs
- the drift kind matches its `kinds`, if it has any
- at least one changed attribute path matches its `paths` globs
- the `when` predicate holds for at least one of those attributes

The matching attribute paths are recorded as what triggered the rule, so a
report can point at the one line out of forty that earned the severity.

## The shipped rules

### Critical — somebody opened something

| Rule | Fires when |
|---|---|
| `sg-ingress-public` | An inbound security group rule now accepts `0.0.0.0/0` or `::/0` |
| `iam-policy-widened` | An IAM policy document gained a wildcard action, resource or principal |
| `s3-public-access` | A bucket's public-access protections were weakened, or its ACL/policy went public |
| `lambda-public-invoke` | A function can now be invoked by a wildcard principal |

### High — a protection was turned off, or something vanished

| Rule | Fires when |
|---|---|
| `sg-ingress-widened` | An inbound rule's CIDR now covers strictly more addresses |
| `encryption-disabled` | An encryption flag went falsey, or a KMS key reference was removed |
| `logging-disabled` | Audit or access logging was turned off |
| `deletion-protection-removed` | Deletion protection off, or `skip_final_snapshot` on |
| `kms-key-disabled` | A KMS key was disabled, or its rotation turned off |
| `resource-deleted` | Terraform can no longer find the resource |
| `iam-policy-changed` | Any other IAM policy difference |
| `route53-record-changed` | A DNS record differs from the code |
| `network-exposure-changed` | Whether the resource has a public address changed |

### Medium — capacity, size, and money

| Rule | Fires when |
|---|---|
| `instance-size-changed` | An instance type or class differs |
| `storage-size-changed` | Allocated storage or a volume size differs |
| `lambda-config-changed` | Memory, timeout, runtime, handler or layers differ |
| `ecs-task-definition-changed` | The running task definition isn't the one the code names |
| `autoscaling-bounds-changed` | `min_size` or `max_size` differs |
| `lb-listener-changed` | A listener, its certificate or its SSL policy differs |
| `backup-retention-changed` | Backup retention differs |

### Low — noise, and things that are fine

| Rule | Fires when |
|---|---|
| `capacity-only-change` | Only `desired_capacity` / `desired_count` differs |
| `tags-only-change` | Only tags differ |
| `default` | Anything no other rule covers |

`default` existing at all is a decision: unexplained drift is still drift,
and the next apply will change it back. It is `low` because we have no
opinion about the attribute yet, not because it doesn't matter — and its
reason says so, and invites you to add a rule.

## Writing a rule

```yaml
  - id: my-rule                    # unique; appears in every report
    severity: high                 # critical | high | medium | low
    reason: >
      What the risk is, not what the rule matched. This sentence is shown
      to the reader.
    types: ["aws_thing", "aws_other_*"]
    paths: ["important_attribute", "nested.*.field"]
    when: became_public            # optional, default any_change
    kinds: ["changed"]              # optional: changed | deleted | replaced
    recommend: revert              # revert | update_code | investigate
    recommend_reason: >
      What a person should do. Crosswind never does it for them.
```

### `types`

Globs against the **Terraform resource type** — `aws_security_group`,
`aws_iam_*`, `*`.

Keyed on the type and **never** the provider name: the same resource is
`registry.terraform.io/hashicorp/aws` under Terraform and
`registry.opentofu.org/hashicorp/aws` under OpenTofu, while the type string
is identical in both.

### `paths`

Globs against the **dotted attribute path** as it appears in a report:
`ingress.0.cidr_blocks.1`, `tags.Owner`, `root_block_device.0.volume_size`.
List elements are indexed by position.

Omit for any attribute. A rule with `paths` that match nothing on a given
resource does not fire, and evaluation continues to the next rule.

### `when` — the closed vocabulary

| Predicate | True when |
|---|---|
| `any_change` | Always. The default. |
| `became_public` | The new value opens something to the world: `0.0.0.0/0`, `::/0`, a `*` principal, a public-access block going off, a `publicly_accessible` flag going on |
| `widened_cidr` | The new CIDR covers strictly more addresses than the old one |
| `encryption_disabled` | A truthy encryption flag went falsey, or a KMS key reference was removed |
| `logging_disabled` | A truthy logging flag went falsey |
| `deletion_protection_removed` | Protection off — or `skip_final_snapshot` on, which removes the same safety net in the opposite direction |
| `iam_widened` | A policy document gained wildcards in `Action`, `Resource` or `Principal` positions |
| `became_larger` | A numeric value or instance size went up |
| `became_smaller` | A numeric value or instance size went down |

**The vocabulary is closed on purpose.** Crosswind reads `.crosswind.yml`
from the repository it is scanning, so an arbitrary expression language there
would be remote code execution with extra steps. The cost is that a genuinely
new kind of predicate needs a Python change; the benefit is that a malicious
config file can at worst mis-score a finding.

A rule naming an unknown predicate fails to load, loudly, with the vocabulary
listed.

Predicates are deliberately forgiving: one that cannot tell returns false, so
an unparseable value falls through to a less specific rule rather than
inventing a critical finding. A truncated or redacted IAM policy scores
nothing rather than guessing.

### `iam_widened` counts wildcards

It compares how many `*` appear in `Action`, `Resource` and `Principal`
positions before and after. A `*` in a `Sid` or a description doesn't count.

This is crude. A real policy-equivalence check needs an IAM evaluation
engine, and a subtly wrong one would produce confident nonsense about
permissions. Counting is honest about what it does and catches the change
that actually happens: somebody pasting `"*"` to unblock themselves.

## Overriding rules

In `.crosswind.yml`, merged by `id`:

- **An existing id replaces that rule in place**, keeping its position in the
  evaluation order. Soften or sharpen a shipped rule without restating the
  rest.
- **A new id goes in front of everything shipped**, because a
  project-specific rule is more specific than anything general we wrote.

```yaml
severity:
  - id: tags-only-change
    severity: medium
    reason: We allocate cost by tag, so a missing tag affects the monthly report.
    types: ["*"]
    paths: ["tags.*"]
    recommend: update_code
    recommend_reason: Put the tag in the code so it stops drifting back.
```

See [`configuration.md`](configuration.md) for the rest.

## Severity vs. ignoring

- **A severity override** is for drift that matters *less* than we scored it.
  You still want to see it.
- **`.crosswindignore`** is for drift that is *expected* — an autoscaling
  group's capacity differing from the code is what autoscaling does.

If you are reaching for an ignore because something is noisy rather than
expected, an override is usually the better answer. And if a shipped rule is
wrong for everyone rather than just for you, please
[open an issue](https://github.com/jetonecloud/crosswind/issues) — the file
is shared, and a rule that annoys you probably annoys someone else.

## Cost estimates

Separate from severity, and much more conservative. A figure appears only
when:

1. The attribute has an unambiguous price — an instance size, a storage size.
2. Both values are in the static table in
   [`cost.yml`](../src/crosswind/data/cost.yml).
3. The difference is at least $1/month.

Every estimate carries a `basis` sentence with the arithmetic in it and says
it is an **upper bound**, because the table is us-east-1 on-demand list price
and Savings Plans, Reserved Instances and Spot all make the real figure
lower.

There is deliberately **no** NAT gateway price, no per-request Lambda price,
and no data transfer price. All of them depend on traffic volume we cannot
see, and Crosswind would have to invent a number to use them. A
plausible-looking invented figure in a report to a manager is worse than no
figure.

The price table carries the date it was last checked. It is a static table
rather than a Pricing API call because an estimate that needs a network round
trip is an estimate that fails in CI, and because the whole point of the
`basis` sentence is that a reader can check it against the AWS pricing page
themselves.
