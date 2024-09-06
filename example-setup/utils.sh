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


# Updates the JSON key given in the first argument with the value given
# in the second argument. Numbers must be \"\" quoted, if they should
# be treated as a JSON string
setjson() {
  if [[ $2 == \"*\" || $2 == \'*\' ]]; then
    # Parameter is string in quotes, use quotes
    json="$(echo "${json}" | jq ".$1 = $2")"
  elif [[ $2 =~ ^[0-9]+$ || $2 == "true" || $2 == "false" ]]; then
    # Parameter is number or boolean, do not use quotes
    json="$(echo "${json}" | jq ".$1 = $2")"
  else
    # Parameter is string, use quotes
    json="$(echo "${json}" | jq ".$1 = \"$2\"")"
  fi
}