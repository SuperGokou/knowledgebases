#!/usr/bin/env sh
set -eu

database_dir=${CLAMAV_DATABASE_DIRECTORY:-/var/lib/clamav}
max_age_seconds=${CLAMAV_DATABASE_MAX_AGE_SECONDS:-604800}
now=$(date +%s)

if ! [ -d "$database_dir" ]; then
  echo "clamav-db-preflight: signature database directory is unavailable" >&2
  exit 66
fi

clamscan --version

for candidates in "main.cvd main.cld" "daily.cvd daily.cld"; do
  selected=
  for candidate in $candidates; do
    if [ -f "$database_dir/$candidate" ]; then
      selected=$database_dir/$candidate
      break
    fi
  done
  if [ -z "$selected" ]; then
    echo "clamav-db-preflight: required signature family is missing: $candidates" >&2
    exit 66
  fi
  if ! test -r "$selected"; then
    echo "clamav-db-preflight: signature database is not readable" >&2
    exit 77
  fi

  mode=$(stat -c '%a' "$selected")
  case "$mode" in
    # The production daemon drops privileges to the image's `clamav` user.
    # Offline signature files are non-secret and root-owned, so require
    # read-only access for the daemon instead of accepting root-only modes.
    444|644) ;;
    *)
      echo "clamav-db-preflight: signature database must be root-owned, daemon-readable, and not group- or world-writable (mode 0444 or 0644)" >&2
      exit 77
      ;;
  esac

  owner_uid=$(stat -c '%u' "$selected")
  if [ "$owner_uid" -ne 0 ]; then
    echo "clamav-db-preflight: signature database must be owned by root" >&2
    exit 77
  fi

  modified_epoch=$(stat -c '%Y' "$selected")
  age_seconds=$((now - modified_epoch))
  if [ "$age_seconds" -lt 0 ] || [ "$age_seconds" -gt "$max_age_seconds" ]; then
    echo "clamav-db-preflight: signature database update time is outside policy" >&2
    exit 69
  fi

  stat -c 'database=%n mode=%a bytes=%s modified_epoch=%Y' "$selected"
  sha256sum "$selected"
  sigtool --info "$selected"
done

echo "clamav-db-preflight: signature database is readable, current, and engine-compatible"
