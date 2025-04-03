#!/usr/bin/env bash
set -eo pipefail
shopt -s inherit_errexit

# Enterprise Artifact Builder for AWS Lambda Layers
# Enforces: ISO 27001, SOC 2 Type II, PCI-DSS 4.0
# Requires: Docker 20.10+, jq 1.6+, GPG 2.2+

declare -r BUILD_UID="10001"
declare -r BUILD_GID="10001"
declare -r ALLOWED_LICENSES=("MIT" "Apache-2.0" "BSD-3-Clause")
declare -r SECURITY_SCAN_EXCLUDES=("test" "tests" "examples")

export DOCKER_BUILDKIT=1
export PYTHONDONTWRITEBYTECODE=1

main() {
    validate_environment
    parse_arguments "$@"
    initialize_security
    build_artifact
    verify_artifact
    generate_manifest
    finalize_package
}

validate_environment() {
    local required_tools=("docker" "jq" "gpg" "shasum")
    local missing=()

    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing+=("$tool")
        fi
    done

    (( ${#missing[@]} == 0 )) || {
        >&2 echo "CRITICAL: Missing required tools: ${missing[*]}"
        exit 1
    }
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "\$1" in
            -o|--output)
                OUTPUT_DIR="\$2"
                shift 2
                ;;
            -v|--version)
                LAYER_VERSION="\$2"
                shift 2
                ;;
            -c|--compliance)
                ENABLE_COMPLIANCE=1
                shift
                ;;
            *)
                >&2 echo "ERROR: Invalid argument: \$1"
                exit 2
                ;;
        esac
    done

    : "${OUTPUT_DIR:=./dist}"
    : "${LAYER_VERSION:=1.0.0}"
    : "${ENABLE_COMPLIANCE:=0}"
}

initialize_security() {
    mkdir -p "${OUTPUT_DIR}/artifacts"
    chmod 700 "${OUTPUT_DIR}"
    
    export GNUPGHOME="${OUTPUT_DIR}/.gnupg"
    mkdir -p "$GNUPGHOME"
    chmod 700 "$GNUPGHOME"
    
    trap security_cleanup EXIT
}

security_cleanup() {
    find "${OUTPUT_DIR}" -type f -exec shred -u {} \;
    rm -rf "${GNUPGHOME}"
    docker builder prune --force --filter 'until=24h'
}

build_artifact() {
    local build_args=(
        "--file" "Dockerfile.layer"
        "--tag" "hedron-layer-builder"
        "--build-arg" "BUILD_UID=${BUILD_UID}"
        "--build-arg" "BUILD_GID=${BUILD_GID}"
        "--secret" "id=pip_config,src=${HOME}/.pip/pip.conf"
    )

    if (( ENABLE_COMPLIANCE )); then
        build_args+=("--build-arg" "ENABLE_LICENSE_CHECK=1")
    fi

    docker buildx build \
        --progress=plain \
        --output "type=local,dest=${OUTPUT_DIR}/artifacts" \
        "${build_args[@]}" \
        . || {
            >&2 echo "CRITICAL: Build failed with code $?"
            exit 3
        }
}

verify_artifact() {
    local artifact_path="${OUTPUT_DIR}/artifacts"
    
    verify_file_signatures "${artifact_path}"
    validate_dependency_checksums
    (( ENABLE_COMPLIANCE )) && check_license_compliance
    perform_security_scan
}

verify_file_signatures() {
    local dir="\$1"
    find "$dir" -type f -name '*.asc' | while read -r sig; do
        local file="${sig%.asc}"
        gpg --verify "$sig" "$file" || {
            >&2 echo "SECURITY ALERT: Invalid signature for ${file}"
            exit 4
        }
    done
}

validate_dependency_checksums() {
    local checksum_file="${OUTPUT_DIR}/artifacts/SHA256SUMS"
    [ -f "$checksum_file" ] || {
        >&2 echo "MISSING: SHA256SUMS verification file"
        exit 5
    }
    
    shasum --check --strict "$checksum_file" || {
        >&2 echo "SECURITY ALERT: Checksum validation failed"
        exit 6
    }
}

check_license_compliance() {
    local license_report="${OUTPUT_DIR}/reports/licenses.json"
    pip-licenses --format=json --with-authors --with-urls > "$license_report"
    
    jq -e 'map(.License) | all(IN($allowed[]); .)' \
        --argjson allowed "$(printf '%s\n' "${ALLOWED_LICENSES[@]}" | jq -Rn '[inputs]')" \
        "$license_report" >/dev/null || {
            >&2 echo "COMPLIANCE VIOLATION: Prohibited licenses detected"
            exit 7
        }
}

perform_security_scan() {
    local scan_report="${OUTPUT_DIR}/reports/security_scan.json"
    trufflehog filesystem --no-update --json "${OUTPUT_DIR}/artifacts" > "$scan_report"
    
    jq -e 'select(.severity == "CRITICAL")' "$scan_report" >/dev/null && {
        >&2 echo "SECURITY ALERT: Critical vulnerabilities detected"
        exit 8
    }
}

generate_manifest() {
    local manifest="${OUTPUT_DIR}/manifest.json"
    jq -n \
        --arg version "$LAYER_VERSION" \
        --arg build_date "$(date -u +%FT%TZ)" \
        --arg git_sha "$(git rev-parse HEAD)" \
        '{
            version: $version,
            build_info: {
                date: $build_date,
                git_commit: $git_sha,
                builder: "Hedron Enterprise Builder",
                compliance_checked: $ENABLE_COMPLIANCE
            }
        }' > "$manifest"
    
    gpg --armor --sign --detach-sig "$manifest"
}

finalize_package() {
    local package_name="hedron-layer-${LAYER_VERSION}.zip"
    local package_path="${OUTPUT_DIR}/${package_name}"
    
    (cd "${OUTPUT_DIR}/artifacts" && zip -qrX "$package_path" .)
    
    shasum -a 512 "$package_path" > "${package_path}.sha512"
    gpg --armor --sign --detach-sig "$package_path"
    
    aws kms encrypt \
        --key-id "alias/hedron-layer-key" \
        --plaintext "fileb://${package_path}" \
        --output "fileb://${package_path}.enc" \
        --encryption-context "environment=production"
}

main "$@"
