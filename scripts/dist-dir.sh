# Sourced by build.sh (bash).
#
# prepare_dist DIR makes DIR ready for build.sh's output. It empties DIR
# only when build.sh could have written it: DIR is missing, empty, or a
# previous build's output, which holds a SHA256SUMS listing telltale
# tarballs and nothing but SHA256SUMS, those tarballs and bin/ with the two
# binaries. Anything else is refused with a message and left alone, and
# prepare_dist returns 1: a symbolic link (also when written with a
# trailing slash, lnk/), a path ending in . or .., and a directory that
# cannot be listed, which is never taken for an empty one.
prepare_dist() {
  local shown=$1 d=$1 p name n=0 listed
  local sum_re='^[0-9a-f]{64}  telltale_[A-Za-z0-9._+-]+_linux_(amd64|arm64)\.tar\.gz$'
  _refuse() {
    printf 'build.sh: %q %s, so it is not a previous build'"'"'s output and build.sh will not empty it; remove it yourself or choose another TELLTALE_DIST_DIR\n' "$shown" "$1" >&2
  }
  # "lnk/" names the directory a link points at; the link itself is what
  # must be judged (and refused).
  while [ "${#d}" -gt 1 ] && [ "${d%/}" != "$d" ]; do
    d=${d%/}
  done
  case "$d" in
    "" | /)
      _refuse "is more than an output directory"
      return 1
      ;;
  esac
  case "${d##*/}" in
    . | ..)
      _refuse "ends in . or .."
      return 1
      ;;
  esac
  # A relative name could start with "-", which find and grep would read
  # as an option.
  case "$d" in
    /*) ;;
    *) d=./$d ;;
  esac
  if [ -L "$d" ]; then
    _refuse "is a symbolic link"
    return 1
  fi
  if [ ! -e "$d" ]; then
    return 0
  fi
  if [ ! -d "$d" ]; then
    _refuse "is not a directory"
    return 1
  fi
  # Each listing ends with an empty name, which find never prints, and only
  # when find succeeded: a listing without it failed and is refused.
  listed=0
  while IFS= read -r -d '' p; do
    if [ -z "$p" ]; then
      listed=1
      continue
    fi
    name=${p##*/}
    n=$((n + 1))
    case "$name" in
      SHA256SUMS | telltale_*_linux_amd64.tar.gz | telltale_*_linux_arm64.tar.gz)
        if [ -L "$p" ] || [ ! -f "$p" ]; then
          _refuse "holds $(printf %q "$name"), which is not a regular file"
          return 1
        fi
        ;;
      bin)
        if [ -L "$p" ] || [ ! -d "$p" ]; then
          _refuse "holds bin, which is not a directory"
          return 1
        fi
        _bin_ok "$p" || return 1
        ;;
      *)
        _refuse "holds $(printf %q "$name")"
        return 1
        ;;
    esac
  done < <(find "$d" -mindepth 1 -maxdepth 1 -print0 && printf '\0')
  if [ "$listed" != 1 ]; then
    _refuse "could not be listed"
    return 1
  fi
  if [ "$n" -gt 0 ]; then
    if [ ! -f "$d/SHA256SUMS" ]; then
      _refuse "has no SHA256SUMS"
      return 1
    fi
    if ! grep -Eq "$sum_re" "$d/SHA256SUMS" || grep -Eqv "$sum_re" "$d/SHA256SUMS"; then
      _refuse "has a SHA256SUMS that build.sh did not write"
      return 1
    fi
  fi
  rm -rf -- "$d"
}

# _bin_ok DIR checks a previous build's bin/ directory (for prepare_dist).
_bin_ok() {
  local q listed=0
  while IFS= read -r -d '' q; do
    if [ -z "$q" ]; then
      listed=1
      continue
    fi
    case "${q##*/}" in
      telltale-linux-amd64 | telltale-linux-arm64)
        if [ -L "$q" ] || [ ! -f "$q" ]; then
          _refuse "holds bin/$(printf %q "${q##*/}"), which is not a regular file"
          return 1
        fi
        ;;
      *)
        _refuse "holds bin/$(printf %q "${q##*/}")"
        return 1
        ;;
    esac
  done < <(find "$1" -mindepth 1 -maxdepth 1 -print0 && printf '\0')
  if [ "$listed" != 1 ]; then
    _refuse "has a bin directory that could not be listed"
    return 1
  fi
}
