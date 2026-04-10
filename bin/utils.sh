#!/bin/bash

# Returns the absolute path
abs_path() {
  if [[ -d "$(dirname "$1")" ]]
  then
    echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")" || true
  fi
}

# Updates the JSON data given in the first argument through setting the key and
# value given in the second and third argument. Automatically detects whether the
# value is valid JSON (number, bool, object, array) or a plain string.
setjson() {
  if [[ "$#" -ne 3 ]]; then
    printf "Error: provided invalid number of parameters: %d: %s\n" "$#" "$*" >&2
    printf "Usage: setjson <json-var> <key> <value>\n" >&2
    return 1
  fi

  local -n ref=$1
  local key=$2
  local value=$3

  if jq -e . <<<"$value" >/dev/null 2>&1; then
    # Value is valid JSON — pass via slurpfile to avoid ARG_MAX
    ref="$(jq --slurpfile v <(printf '%s' "$value") ".$key = \$v[0]" <<<"$ref")"
  else
    # Plain string — pass via --arg (handles all escaping)
    ref="$(jq --arg v "$value" ".$key = \$v" <<<"$ref")"
  fi
}

# Updates the JSON data given in the first argument through replacing the array
# at the key given in the second argument. Can handle entire JSON arrays and
# single string values. Multiple string values can be passed as extra arguments.
setarr() {
  if [[ "$#" -lt 3 ]]; then
    printf "Error: provided invalid number of parameters: %d\n" "$#" >&2
    printf "Usage: setarr <json-var> <key> <values...>\n" >&2
    return 1
  fi

  local -n ref=$1
  local key=$2
  shift 2

  # Clear existing array
  ref="$(jq "del(.$key[])" <<<"$ref")"

  # If single arg is a JSON array, assign directly via slurpfile
  if [[ $# -eq 1 ]] && jq -e 'type == "array"' <<<"$1" >/dev/null 2>&1; then
    ref="$(jq --slurpfile v <(printf '%s' "$1") ".$key = \$v[0]" <<<"$ref")"
  else
    for param in "$@"; do
      ref="$(jq --arg v "$param" ".$key += [\$v]" <<<"$ref")"
    done
  fi
}

# Updates the JSON data given in the first argument through extending the array
# given in the second argument with the value given in the third argument
extendarr() {
  if [[ "$#" -ne 3 ]]; then
    printf "Error: provided invalid number of parameters: %d\n" "$#" >&2
    printf "Usage: extendarr <json-var> <key> <value>\n" >&2
    return 1
  fi

  local -n ref=$1
  local key=$2
  local param=$3

  # Determine if value is valid JSON — pass via slurpfile to avoid ARG_MAX
  if jq -e type <<<"$param" >/dev/null 2>&1; then
    ref="$(jq --slurpfile v <(printf '%s' "$param") \
      ".$key += (if \$v[0] | type == \"array\" then \$v[0] else [\$v[0]] end)" <<<"$ref")"
  else
    ref="$(jq --arg v "$param" ".$key += [\$v]" <<<"$ref")"
  fi
}