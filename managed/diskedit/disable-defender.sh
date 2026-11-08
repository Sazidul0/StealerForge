#!/bin/sh
# Offline registry edit of the base disk before it is sealed. Tamper Protection blocks every in-guest way to
# turn Microsoft Defender off, and signatures updated during installation would quarantine samples.
# libguestfs edits the hives inside its own small VM; nothing is mounted on the host.
set -eu
disk="$1"
export LIBGUESTFS_BACKEND=direct
number() { sed 's/^dword://' | tr -d '\r\n '; }
current=$(virt-win-reg "$disk" 'HKLM\SYSTEM\Select' Current | number)
set_name=$(printf 'ControlSet%03d' "$((0x$current))")
sed "s/CurrentControlSet/$set_name/" /opt/diskedit/defender.reg > /tmp/defender.reg
virt-win-reg --merge "$disk" /tmp/defender.reg
for service in WinDefend WdFilter WdBoot WdNisSvc WdNisDrv; do
  value=$(virt-win-reg "$disk" "HKLM\\SYSTEM\\$set_name\\Services\\$service" Start | number)
  [ "$((0x$value))" -eq 4 ] || { echo "$service Start is $value after merge" >&2; exit 1; }
done
value=$(virt-win-reg "$disk" 'HKLM\SOFTWARE\Microsoft\Windows Defender\Features' TamperProtection | number)
[ "$((0x$value))" -eq 4 ] || { echo "TamperProtection is $value after merge" >&2; exit 1; }
echo "Microsoft Defender disabled offline in $set_name"
