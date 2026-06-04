#!/bin/bash


main() {

  local host=$1
  shift

  # optional
  local user=$1
  shift

  local usageStr="$(basename "${BASH_SOURCE[0]}") <host> [user]"

  if [[ -z "$host" ]] ; then
    echo "$usageStr" >&2
    return 1
  fi

  if [[ -n "$@" ]]; then
    echo "Too many parameters passed" >&2
    return 1
  fi

  local userStr
  if [[ -n "$user" ]]; then
    userStr="$user""@"
  fi

  ssh-keygen -R "$host" || return 1  
  ssh-copy-id -o StrictHostKeyChecking=no "$userStr$host" || return 1

}

main $@

