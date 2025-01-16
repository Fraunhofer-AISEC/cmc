dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"

case "${PATH}" in ""|"${dir}"*) ;; *) PATH="${dir}:${PATH}";; esac
