# Installation

Crosswind is a Python package distributed through
[GitHub releases](https://github.com/jetonecloud/crosswind/releases) rather
than PyPI. It needs Terraform or OpenTofu on your `PATH` to do anything other
than `crosswind demo`.

Python 3.11 or newer.

Pick a tag and stay on it. There is no `latest` that moves under you, which
is the point — for a tool that reads your state, knowing exactly what you are
running is worth one extra token in the install command.

## pipx

The usual way. `pipx` keeps Crosswind and its dependencies in their own
virtualenv rather than in your system Python.

```sh
pipx install git+https://github.com/jetonecloud/crosswind@v0.1.0
crosswind demo
```

To upgrade, install the new tag over the old one:

```sh
pipx install --force git+https://github.com/jetonecloud/crosswind@v0.2.0
```

## uv

```sh
uv tool install git+https://github.com/jetonecloud/crosswind@v0.1.0
```

Or without installing anything permanently:

```sh
uvx --from git+https://github.com/jetonecloud/crosswind@v0.1.0 crosswind demo
```

## From the release wheel, without git

For an image or a runner with no `git`. The wheel is attached to every
release:

```sh
VERSION=0.1.0
BASE=https://github.com/jetonecloud/crosswind/releases/download/v$VERSION

curl -fsSLO "$BASE/crosswind-$VERSION-py3-none-any.whl"
pipx install "./crosswind-$VERSION-py3-none-any.whl"
```

### Verifying what you downloaded

Every release carries a `checksums.txt`. Worth the thirty seconds for a tool
that reads your Terraform state:

```sh
gh release download v0.1.0 --repo jetonecloud/crosswind
sha256sum --check --ignore-missing checksums.txt
pipx install ./crosswind-0.1.0-py3-none-any.whl
```

Releases also carry a signed build provenance attestation, which is what
proves the wheel was built by the release workflow from this repository
rather than uploaded by hand:

```sh
gh attestation verify crosswind-0.1.0-py3-none-any.whl \
  --repo jetonecloud/crosswind
```

## pip

Works, but put it in a virtualenv — Crosswind pulls in `boto3`, and a
system-wide `boto3` upgrade is a good way to break something else.

```sh
python -m venv ~/.venvs/crosswind
~/.venvs/crosswind/bin/pip install \
  git+https://github.com/jetonecloud/crosswind@v0.1.0
~/.venvs/crosswind/bin/crosswind demo
```

## In a requirements file

```
crosswind @ git+https://github.com/jetonecloud/crosswind@v0.1.0
```

Pin the tag, not a branch. `@main` will silently change what your CI runs.

## Why not PyPI

Partly because a drift checker that reads your state is a thing you should be
deliberate about installing, and a tag in the command is a cheap way to be
deliberate. Partly because publishing to PyPI means claiming a name and
taking on the obligation not to break anyone depending on it, which is a
commitment worth making once the schema has stopped moving rather than at
0.1.0.

If that changes, the install command will get shorter and this section will
say so.

## Docker

For CI, or if you'd rather not install a Python toolchain. The image includes
OpenTofu, so there is nothing else to install.

```sh
docker run --rm ghcr.io/jetonecloud/crosswind:latest demo
```

A real scan needs your stacks, your credentials, and somewhere to put the
reports:

```sh
docker run --rm \
  -v "$PWD:/stacks:ro" \
  -v "$HOME/.aws:/home/crosswind/.aws:ro" \
  -v "$PWD/reports:/out" \
  ghcr.io/jetonecloud/crosswind:latest \
  scan --path /stacks --format html --output-dir /out
```

Both mounts are `:ro`. Crosswind does not write to your working tree or read
anything from `~/.aws` other than credentials, and mounting them read-only
means you don't have to take our word for either.

The container runs as uid 1000, which lines up with the first human account
on most hosts. If your uid differs, the output directory needs to be writable
by uid 1000 — `chmod 777` on a throwaway directory, or `--user "$(id -u)"`
with a `-v` for a home directory it can write to.

### Why the image ships OpenTofu

`releases.hashicorp.com` and `registry.terraform.io` are geo-restricted under
HashiCorp's trade controls, and return an HTTP error page instead of a
download in the affected regions. An image that fetched Terraform could not
be built there, and a stack could not be initialised either, since provider
downloads go to the same registry.

Everything Crosswind reads is identical between the two tools. Both emit plan
JSON `format_version` 1.2, both put drift in `resource_drift`, and the test
suite runs against both. The only difference Crosswind sees is the registry
hostname inside `provider_name`, which nothing keys on.

If you want Terraform in the image and you can download it:

```sh
docker build --build-arg FLAVOUR=terraform --build-arg TERRAFORM_VERSION=1.9.8 \
  -t crosswind:terraform .
```

Or mount your own binary and point `--binary` at it, which works regardless
of what the image contains:

```sh
docker run --rm \
  -v "$PWD:/stacks:ro" \
  -v "$(command -v terraform):/usr/local/bin/terraform:ro" \
  ghcr.io/jetonecloud/crosswind:latest \
  scan --path /stacks --binary terraform
```

## From a checkout

For development, or to run it before it's published:

```sh
git clone https://github.com/jetonecloud/crosswind.git
cd crosswind
uv sync --all-extras --dev
uv run crosswind demo
```

[`CONTRIBUTING.md`](../CONTRIBUTING.md) has the rest of the development
setup.

## Terraform or OpenTofu

Crosswind drives whichever it finds on `PATH`, preferring `terraform` when
both are present. It asks the binary what it is rather than trusting the
filename, because `tofu` symlinked as `terraform` is a real thing people do
and the two differ in ways that matter.

```sh
crosswind scan --path . --binary tofu
crosswind scan --path . --binary /opt/homebrew/bin/terraform
```

**Use the same tool your team applies with.** The plan JSON is identical, but
the provider lock file is written by one tool and read by the other, and a
mismatch shows up as a stack that could not be checked.

### The stack must already be initialised

Crosswind runs `init -lockfile=readonly` so that it never writes to your
working tree. That means a stack with no `.terraform.lock.hcl` fails rather
than having one created for it, and is reported as "could not check" with the
fix named:

```sh
cd infra/prod
terraform init        # once, and commit the lock file it creates
```

Creating a lock file on your behalf would be a write to your tree and a
change to a file that is normally committed, so Crosswind doesn't.

## Checking it works

```sh
crosswind version
crosswind demo                      # a full report from fixtures
crosswind doctor --path infra/prod  # the real checks, in two seconds
```

`doctor` is the useful one. It checks the binary, finds your stacks, tries a
real `init` to see whether the state backend is readable, checks your
credentials, and tries one CloudTrail lookup — then tells you which of those
would fail. Running it before your first scan saves waiting on a refresh to
find out you have no credentials.

Missing credentials are a warning rather than a failure. Drift detection
works without them; every finding will just say `unknown`.

## AWS credentials

Crosswind uses the standard AWS credential chain and never accepts a key
directly. There is no `--access-key` flag, no prompt, and no config file
field — a tool that takes a pasted secret teaches people to paste secrets.

Anything that works for the AWS CLI works here:

```sh
aws sso login --profile prod
crosswind scan --path infra/prod --profile prod

AWS_PROFILE=prod crosswind scan --path infra/prod

crosswind scan --path infra/prod \
  --role-arn arn:aws:iam::111111111111:role/CrosswindReadOnlyRole
```

`--role-arn` assumes a role *from* whatever the chain already produced, so it
composes with `--profile` and with an instance role.

Credentials are only used for CloudTrail attribution. Terraform resolves its
own credentials through its provider configuration in the usual way, so a
stack with a provider-level `assume_role` block keeps working.

See [`iam/README.md`](../iam/README.md) for which permissions are needed and
an honest account of how broad the refresh permissions have to be.
