#!/bin/bash

abs_path() {
  if [[ -d "$(dirname "$1")" ]]
  then
    echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")" || true
  fi
}

extendarr() {
	local key=$1
	shift
  local param=$1

  # Add new value
  json="$(echo "${json}" | jq ".${key} += [${param}]")"
}