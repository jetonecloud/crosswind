# Crosswind in a container, for CI and for people who'd rather not install a
# Python toolchain.
#
#   docker run --rm \
#     -v "$PWD:/stacks:ro" \
#     -v "$HOME/.aws:/home/crosswind/.aws:ro" \
#     -v "$PWD/reports:/out" \
#     ghcr.io/jetonecloud/crosswind:latest \
#     scan --path /stacks --format html --output-dir /out
#
# Note the `:ro` on the stack mount. Crosswind does not write to your working
# tree, and mounting it read-only means you do not have to take our word for
# it.
#
# ---------------------------------------------------------------------------
# Why this image ships OpenTofu rather than Terraform
# ---------------------------------------------------------------------------
# A drift checker needs a binary to drive, so one is baked in. We ship
# OpenTofu, for a reason that is worth stating plainly rather than leaving
# people to discover:
#
# `releases.hashicorp.com` and `registry.terraform.io` are geo-restricted
# under HashiCorp's trade controls. In the affected regions they return an
# HTTP error page instead of a download, which means a Dockerfile that
# fetches Terraform simply cannot be built there — and nor can a stack be
# initialised, since provider downloads go to the same registry. OpenTofu's
# release assets and registry have no such restriction.
#
# Everything Crosswind reads is identical between the two. Both emit plan
# JSON `format_version` 1.2, both put drift in `resource_drift`, and the
# whole test suite runs against both. The only difference Crosswind sees is
# the registry hostname inside `provider_name`, which nothing keys on.
#
# If you want Terraform in the image instead, and you are somewhere it can be
# downloaded:
#
#   docker build --build-arg FLAVOUR=terraform --build-arg TERRAFORM_VERSION=1.9.8 .
#
# Or mount your own binary and point `--binary` at it, which works whatever
# this image contains.

FROM python:3.12-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# A virtualenv so the final stage can take the whole thing in one COPY,
# without pip, its caches, or the build backend coming along.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /src
# Only what the build backend reads. Keeping tests and docs out means a docs
# change does not invalidate the layer that installs the dependencies.
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install .


FROM python:3.12-slim

# `tofu` (default) or `terraform`. See the note at the top of this file.
ARG FLAVOUR=tofu
ARG OPENTOFU_VERSION=1.13.2
ARG TERRAFORM_VERSION=1.9.8

# Set by the release workflow from the tag; only the labels use it, so a
# local `docker build` with no --build-arg still produces a working image.
ARG VERSION=0.0.0-dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="Crosswind" \
      org.opencontainers.image.description="Read-only Terraform drift checker: what changed, who changed it, and why it matters." \
      org.opencontainers.image.url="https://github.com/jetonecloud/crosswind" \
      org.opencontainers.image.source="https://github.com/jetonecloud/crosswind" \
      org.opencontainers.image.documentation="https://github.com/jetonecloud/crosswind/blob/main/docs/installation.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Jet1" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # The CLI checkpoint call is the one piece of network traffic these
    # binaries make that has nothing to do with your infrastructure.
    # Crosswind promises no telemetry; that has to include telemetry we would
    # otherwise cause.
    CHECKPOINT_DISABLE=1 \
    TF_IN_AUTOMATION=1

# Both downloads are verified against the publisher's own SHA256SUMS for the
# exact version, so a version bump stays checksum-verified.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl unzip; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) goarch=amd64 ;; \
      arm64) goarch=arm64 ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    case "$FLAVOUR" in \
      tofu) \
        base="https://github.com/opentofu/opentofu/releases/download/v${OPENTOFU_VERSION}"; \
        zip="tofu_${OPENTOFU_VERSION}_linux_${goarch}.zip"; \
        sums="tofu_${OPENTOFU_VERSION}_SHA256SUMS"; \
        ;; \
      terraform) \
        base="https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}"; \
        zip="terraform_${TERRAFORM_VERSION}_linux_${goarch}.zip"; \
        sums="terraform_${TERRAFORM_VERSION}_SHA256SUMS"; \
        ;; \
      *) echo "FLAVOUR must be tofu or terraform, got: $FLAVOUR" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo "/tmp/${zip}" "${base}/${zip}"; \
    curl -fsSLo /tmp/sums "${base}/${sums}"; \
    (cd /tmp && grep " ${zip}\$" sums | sha256sum --check --strict -); \
    unzip -q "/tmp/${zip}" -d /usr/local/bin; \
    chmod 0755 "/usr/local/bin/${FLAVOUR}"; \
    rm -rf "/tmp/${zip}" /tmp/sums; \
    apt-get purge -y --auto-remove curl unzip; \
    rm -rf /var/lib/apt/lists/*; \
    "${FLAVOUR}" version

COPY --from=build /opt/venv /opt/venv

# Nothing here needs root, and a tool that reads someone's AWS credentials
# and Terraform state is the last thing that should ask for it. uid 1000 is
# the usual first human account, so a bind-mounted ~/.aws and a writable
# output directory line up without --user on most hosts.
RUN useradd --create-home --uid 1000 crosswind \
    && mkdir /out /stacks \
    && chown crosswind:crosswind /out

USER crosswind

# Where reports land by default. `--output-dir` defaults to the working
# directory, so `-v "$PWD/reports:/out"` is all a caller needs.
WORKDIR /out

ENTRYPOINT ["crosswind"]
CMD ["--help"]
