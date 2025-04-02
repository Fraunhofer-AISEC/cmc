dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"

case "${PATH}" in ""|"${dir}/bin"*) ;; *) PATH="${dir}/bin:${PATH}";; esac

function _cmc-docker () {
    _command_offset 1
}

complete -F _cmc-docker 'cmc-docker'