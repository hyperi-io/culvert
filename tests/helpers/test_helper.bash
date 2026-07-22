#!/usr/bin/env bash
#  Project:      culvert
#  File:         test_helper.bash
#  Purpose:      Common test utilities
#  Language:     Bash
#
#  License:      Apache-2.0
#  Copyright:    (c) 2026 HYPERI PTY LIMITED

# Determine test root directory
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_ROOT="$(cd "${TEST_ROOT}/.." && pwd)"

# Export paths for test scripts
export TEST_ROOT
export PROJECT_ROOT
export SCRIPTS_DIR="${PROJECT_ROOT}/scripts"
export FIXTURES_DIR="${TEST_ROOT}/fixtures"

#===============================================================================
# Assertion Helpers
#===============================================================================

# Assert file exists
assert_file_exists() {
    local file="${1}"
    if [[ ! -f "${file}" ]]; then
        echo "Expected file to exist: ${file}" >&2
        return 1
    fi
}

# Assert directory exists
assert_dir_exists() {
    local dir="${1}"
    if [[ ! -d "${dir}" ]]; then
        echo "Expected directory to exist: ${dir}" >&2
        return 1
    fi
}

# Assert file contains string
assert_file_contains() {
    local file="${1}"
    local pattern="${2}"
    if ! grep -q "${pattern}" "${file}" 2>/dev/null; then
        echo "Expected file '${file}' to contain: ${pattern}" >&2
        return 1
    fi
}

# Assert string contains substring
assert_contains() {
    local haystack="${1}"
    local needle="${2}"
    if [[ "${haystack}" != *"${needle}"* ]]; then
        echo "Expected '${haystack}' to contain '${needle}'" >&2
        return 1
    fi
}

# Assert strings are equal
assert_equal() {
    local expected="${1}"
    local actual="${2}"
    if [[ "${expected}" != "${actual}" ]]; then
        echo "Expected: '${expected}'" >&2
        echo "Actual:   '${actual}'" >&2
        return 1
    fi
}

# Assert command succeeds (status/output are BATS variables set by 'run')
assert_success() {
    # shellcheck disable=SC2154
    if [[ "${status}" -ne 0 ]]; then
        echo "Expected command to succeed (exit 0), got exit ${status}" >&2
        # shellcheck disable=SC2154
        echo "Output: ${output}" >&2
        return 1
    fi
}

# Assert command fails (status/output are BATS variables set by 'run')
assert_failure() {
    # shellcheck disable=SC2154
    if [[ "${status}" -eq 0 ]]; then
        echo "Expected command to fail (exit != 0), got exit 0" >&2
        # shellcheck disable=SC2154
        echo "Output: ${output}" >&2
        return 1
    fi
}

#===============================================================================
# Setup/Teardown Helpers
#===============================================================================

# Create temporary directory for test
create_temp_dir() {
    local prefix="${1:-bats-test}"
    mktemp -d -t "${prefix}.XXXXXX"
}

# Clean up temporary directory
cleanup_temp_dir() {
    local dir="${1}"
    if [[ -d "${dir}" ]] && [[ "${dir}" == /tmp/* ]]; then
        rm -rf "${dir}"
    fi
}

# Generate random string
random_string() {
    local length="${1:-8}"
    head -c 100 /dev/urandom | tr -dc 'a-z0-9' | head -c "${length}"
}

#===============================================================================
# Mock Helpers
#===============================================================================

# Create mock command
create_mock() {
    local cmd="${1}"
    local output="${2:-}"
    local exit_code="${3:-0}"
    local mock_dir="${BATS_TEST_TMPDIR}/mocks"

    mkdir -p "${mock_dir}"
    cat > "${mock_dir}/${cmd}" << EOF
#!/bin/bash
echo "${output}"
exit ${exit_code}
EOF
    chmod +x "${mock_dir}/${cmd}"
    export PATH="${mock_dir}:${PATH}"
}

# Remove mock command
remove_mock() {
    local cmd="${1}"
    local mock_dir="${BATS_TEST_TMPDIR}/mocks"
    rm -f "${mock_dir}/${cmd}"
}

#===============================================================================
# Certificate Helpers
#===============================================================================

# Generate self-signed test certificate
generate_test_cert() {
    local cn="${1:-test.example.com}"
    local output_dir="${2:-.}"

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 \
        -keyout "${output_dir}/test.key" \
        -out "${output_dir}/test.crt" \
        -days 1 \
        -nodes \
        -subj "/CN=${cn}" \
        2>/dev/null
}

# Verify certificate is valid
verify_cert() {
    local cert_file="${1}"
    openssl x509 -in "${cert_file}" -noout -text >/dev/null 2>&1
}

#===============================================================================
# Network Helpers
#===============================================================================

# Check if port is open
port_is_open() {
    local host="${1}"
    local port="${2}"
    nc -z "${host}" "${port}" 2>/dev/null
}

# Wait for port to be open
wait_for_port() {
    local host="${1}"
    local port="${2}"
    local timeout="${3:-30}"
    local count=0

    while ! port_is_open "${host}" "${port}"; do
        sleep 1
        count=$((count + 1))
        if [[ ${count} -ge ${timeout} ]]; then
            echo "Timeout waiting for ${host}:${port}" >&2
            return 1
        fi
    done
}
