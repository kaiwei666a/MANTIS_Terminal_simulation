#!/bin/bash

clean_crontab() {
  chattr -ia "$1"
  grep -vE 'wget|curl|/dev/tcp|/tmp|\.sh|nc|bash -i|sh -i|base64 -d' "$1" >/tmp/clean_crontab
  mv /tmp/clean_crontab "$1"
}

systemctl disable c3pool_miner
systemctl stop c3pool_miner

chattr -ia /var/spool/cron/crontabs
for user_cron in /var/spool/cron/crontabs/*; do
  [ -f "$user_cron" ] && clean_crontab "$user_cron"
done

for system_cron in /etc/crontab /etc/crontabs; do
  [ -f "$system_cron" ] && clean_crontab "$system_cron"
done

for dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
  chattr -ia "$dir"
  for system_cron in "$dir"/*; do
    [ -f "$system_cron" ] && clean_crontab "$system_cron"
  done
done

clean_crontab /etc/anacrontab

for i in /tmp /var/tmp /dev/shm; do
  rm -rf $i/*
done
