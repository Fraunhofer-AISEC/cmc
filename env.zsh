dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)"

case "${PATH}" in ""|"${dir}/bin"*) ;; *) PATH="${dir}/bin:${PATH}";; esac

function _cmc-docker () {
  CURRENT=$((CURRENT - 1))
  _normal
}

compdef _cmc-docker cmc-docker

compdef vm-ssh='ssh'
compdef vm-scp='scp'
