#compdef fido2kpxc

_fido2kpxc() {
  local -a commands
  commands=(
    'enroll:create the vault with the first security key'
    'enroll-key:add a backup security key'
    'remove-key:remove a key and move the vault to a new data key'
    'set-secret:store the password for a database'
    'remove-secret:remove the stored password for a database'
    'list-keys:list the labels of the enrolled keys'
    'list-databases:list the databases with a stored password'
    'completions:print a shell completion script'
    'help:show the commands and options'
  )
  if (( CURRENT == 2 )); then
    if [[ $PREFIX == -* ]]; then
      compadd -- --help -h
    else
      _describe 'command' commands
    fi
    return
  fi
  case $words[2] in
    enroll)
      (( CURRENT == 3 )) && compadd -- --label
      (( CURRENT == 5 )) && compadd -- --database
      ;;
    enroll-key)
      (( CURRENT == 3 )) && compadd -- --label
      ;;
    set-secret|remove-secret)
      if (( CURRENT == 3 )); then
        compadd -- --database
      elif (( CURRENT == 4 )); then
        compadd -- ${(f)"$(fido2kpxc list-databases 2>/dev/null)"}
      fi
      ;;
    remove-key)
      if (( CURRENT == 3 )); then
        compadd -- --label
      elif (( CURRENT == 4 )); then
        compadd -- ${(f)"$(fido2kpxc list-keys 2>/dev/null)"}
      fi
      ;;
    completions)
      (( CURRENT == 3 )) && compadd zsh
      ;;
  esac
}

# Works both as an autoloaded file in $fpath and with `source <(fido2kpxc completions zsh)`.
if [[ $zsh_eval_context[-1] == loadautofunc ]]; then
  _fido2kpxc "$@"
else
  compdef _fido2kpxc fido2kpxc
fi
