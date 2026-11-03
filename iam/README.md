# Permissions

Crosswind needs three different kinds of access, and they are very different
sizes. This file is about the third one, because it is the one that deserves
an argument rather than a shrug.

## 1. CloudTrail lookup — one action

```
cloudtrail:LookupEvents
sts:GetCallerIdentity
```

That is the whole of attribution. `LookupEvents` reads the CloudTrail event
history; it cannot read trail configuration, cannot read data events, and
cannot write anything. `GetCallerIdentity` is how `doctor` tells you which
account you are pointed at.

These are the only two API calls Crosswind itself makes. Everything below is
permissions **Terraform** needs, not permissions Crosswind wants.

## 2. State read — scoped to one bucket and one key

```
s3:GetObject, s3:GetObjectVersion, s3:ListBucket,
s3:GetBucketLocation, s3:GetBucketVersioning
kms:Decrypt, kms:DescribeKey
```

Scoped to your state bucket's ARN and your state key's ARN, not `"*"`. Note
there is no `kms:Encrypt` and no `kms:GenerateDataKey`: Crosswind reads state
and never writes it, so it has no use for either. If you do not use an S3
backend, deploy the template with `StateBucket` empty and this statement is
omitted rather than widened.

If your state is in Terraform Cloud, an HTTP backend, or Consul, you need
whatever read credential that backend wants instead, and none of this applies.

## 3. Refresh — broad, and here is the honest version

`terraform plan -refresh-only` works by asking every provider to re-read
every resource in your state and compare it to what is recorded. That means
the permissions needed are **a function of what your stacks manage**, not of
anything Crosswind decides. A stack with RDS instances needs
`rds:DescribeDBInstances`. A stack with forty resource types needs the read
action for all forty.

So the shipped policy is broad: `Describe*`, `Get*` and `List*` across the
services people commonly manage with Terraform, on `Resource: "*"`.

**Be clear about what that is.** It is read-only — there is no action in it
that creates, modifies or deletes anything, and `tests/test_policy.py`
asserts that on every commit. But "read-only across most of your account" is
still a lot. It can read:

- IAM policy documents, including trust policies
- S3 bucket policies and configuration (not object contents — that would be
  `s3:GetObject` on your data buckets, which is not granted)
- Secrets Manager secret *metadata* (`DescribeSecret`, not `GetSecretValue`)
- Lambda environment variables, via `lambda:GetFunctionConfiguration`
- Security group rules, VPC layout, and every resource tag

That last one is worth sitting with: `lambda:GetFunctionConfiguration`
returns environment variables, and people put credentials in environment
variables. A role with this policy can read those. Crosswind redacts them
before they reach a report, but the role can read them, and a different tool
holding the same role could do whatever it liked with them.

### Why we ship the broad version anyway

Because the narrow version cannot be generated without reading your state,
and asking you to grant permissions to read your state in order to work out
which permissions to grant is circular. The broad policy is the option that
works on the first try.

### The narrowest practical option

If you would rather not grant the above — and for a production account that
is a reasonable position — do this instead:

1. **Deploy the role without the refresh policy:**

   ```sh
   aws cloudformation deploy \
     --template-file iam/role.cfn.yaml \
     --stack-name crosswind-role \
     --capabilities CAPABILITY_NAMED_IAM \
     --parameter-overrides \
       GitHubRepository=your-org/your-repo \
       StateBucket=your-tfstate-bucket \
       IncludeRefreshPermissions=false
   ```

2. **Work out what your stacks actually need.** The resource types in your
   state are the answer, and you can get them without granting anything new:

   ```sh
   terraform state list | sed 's/\..*//' | sed 's/^module\..*\.//' | sort -u
   ```

3. **Write a policy with only those services' read actions**, and attach it
   to the role. `ec2:DescribeInstances` rather than `ec2:Describe*`, if you
   have the patience.

4. **Run `crosswind doctor`.** A missing permission shows up as a stack that
   could not be checked, with the denied action named in the error — so you
   can add exactly what is missing and no more. Iterating this way converges
   in two or three passes and gives you a policy that is genuinely minimal
   for your estate.

The reason we do not ship that policy is that we cannot write it for you. The
reason we document it is that for some accounts it is the right answer.

### What you cannot narrow away

`cloudtrail:LookupEvents` has no resource-level permissions — AWS does not
support scoping it to a resource or a region, so it is `"*"` or nothing. If
that is unacceptable, run with `--no-attribution`: drift detection works
fully without it, and every finding will say `unknown`.

## Alternative: use a role you already have

Crosswind does not need its own role. If you already have a read-only role
for Terraform plans — most teams running plan-on-PR do — then add
`cloudtrail:LookupEvents` to it and pass it with `--role-arn`. That is fewer
moving parts and one less thing to audit.

The standard AWS `ReadOnlyAccess` managed policy also covers everything here,
including `LookupEvents`. It is *wider* than this template, not narrower —
notably it includes `s3:GetObject` on your actual data — so it is the
convenient option rather than the careful one.

## GitHub Actions OIDC

The template's OIDC trust policy pins to a single branch:

```
repo:owner/repo:ref:refs/heads/main
```

Not `repo:owner/repo:*`. The wildcard form lets a workflow triggered by a
pull request — including from a fork, on some configurations — assume the
role. For a role that can read your state and your IAM policies, that is the
difference between a drift checker and a credential.

It needs the GitHub OIDC provider to exist in your account already. If it
does not:

```sh
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com
```

## Verifying for yourself

[`policy.json`](policy.json) is the same permission set as a flat document.
Check it before you deploy anything:

```sh
# Every action, sorted. There should be no Create/Put/Delete/Update/Modify.
jq -r '.Statement[].Action[]' iam/policy.json | sort -u
```

CI runs a stricter version of that check on every commit: an action that is
not a `Get`, `List` or `Describe` (plus the two named exceptions,
`cloudtrail:LookupEvents` and `apigateway:GET`) fails the build.
