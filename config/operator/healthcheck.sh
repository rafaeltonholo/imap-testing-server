#!/bin/sh

set -f

is_decimal() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

is_positive_decimal() {
  is_decimal "$1" || return 1
  case "$1" in
    *[1-9]*) return 0 ;;
    *) return 1 ;;
  esac
}

is_hex_width() {
  case "$1" in
    ''|*[!0-9A-F]*) return 1 ;;
  esac
  case "${#1}" in
    "$2") return 0 ;;
    *) return 1 ;;
  esac
}

check_pair() {
  pair_value=$1
  pair_left_width=$2
  pair_right_width=$3

  case "$pair_value" in
    *:*) ;;
    *) return 1 ;;
  esac
  pair_left=${pair_value%%:*}
  pair_right=${pair_value#*:}
  case "$pair_left:$pair_right" in
    *:*:*) return 1 ;;
  esac
  is_hex_width "$pair_left" "$pair_left_width" || return 1
  is_hex_width "$pair_right" "$pair_right_width" || return 1
}

check_service_status() {
  service_status=$1
  service_seen_keys='|'
  service_process_count_seen=0
  service_throttle_secs_seen=0
  service_doveadm_stop_seen=0

  while IFS= read -r service_line; do
    case "$service_line" in
      *': '*) ;;
      *) return 1 ;;
    esac

    service_key=${service_line%%:*}
    service_value=${service_line#*: }
    case "$service_key" in
      ''|*[!A-Za-z0-9_-]*) return 1 ;;
    esac
    case "$service_seen_keys" in
      *"|$service_key|"*) return 1 ;;
    esac
    service_seen_keys="$service_seen_keys$service_key|"

    case "$service_key" in
      process_count)
        is_positive_decimal "$service_value" || return 1
        service_process_count_seen=1
        ;;
      throttle_secs)
        case "$service_value" in
          0) service_throttle_secs_seen=1 ;;
          *) return 1 ;;
        esac
        ;;
      doveadm_stop)
        case "$service_value" in
          n) service_doveadm_stop_seen=1 ;;
          *) return 1 ;;
        esac
        ;;
    esac
  done <<SERVICE_STATUS_EOF
$service_status
SERVICE_STATUS_EOF

  case "$service_process_count_seen:$service_throttle_secs_seen:$service_doveadm_stop_seen" in
    1:1:1) return 0 ;;
    *) return 1 ;;
  esac
}

check_proc_file() {
  proc_path=$1
  proc_address_width=$2
  proc_remote_header=$3
  proc_seen_slots='|'

  {
    IFS=' ' read -r proc_h1 proc_h2 proc_h3 proc_h4 proc_h5 proc_h6 \
      proc_h7 proc_h8 proc_h9 proc_h10 proc_h11 proc_h12 proc_h_extra || return 1
    case "$proc_h1|$proc_h2|$proc_h3|$proc_h4|$proc_h5|$proc_h6|$proc_h7|$proc_h8|$proc_h9|$proc_h10|$proc_h11|$proc_h12|$proc_h_extra" in
      "sl|local_address|$proc_remote_header|st|tx_queue|rx_queue|tr|tm->when|retrnsmt|uid|timeout|inode|") ;;
      *) return 1 ;;
    esac

    while :; do
      proc_line=
      if IFS= read -r proc_line; then
        :
      else
        case "$proc_line" in
          '') break ;;
          *) return 1 ;;
        esac
      fi
      IFS=' ' read -r proc_slot proc_local proc_remote proc_state \
        proc_queue proc_timer proc_retransmit proc_uid proc_timeout proc_inode proc_extra <<PROC_ROW_EOF
$proc_line
PROC_ROW_EOF
      case "$proc_slot" in
        *:) proc_slot_number=${proc_slot%:} ;;
        *) return 1 ;;
      esac
      is_decimal "$proc_slot_number" || return 1
      case "$proc_seen_slots" in
        *"|$proc_slot_number|"*) return 1 ;;
      esac
      proc_seen_slots="$proc_seen_slots$proc_slot_number|"

      check_pair "$proc_local" "$proc_address_width" 4 || return 1
      check_pair "$proc_remote" "$proc_address_width" 4 || return 1
      is_hex_width "$proc_state" 2 || return 1
      check_pair "$proc_queue" 8 8 || return 1
      check_pair "$proc_timer" 2 8 || return 1
      is_hex_width "$proc_retransmit" 8 || return 1
      is_decimal "$proc_uid" || return 1
      is_decimal "$proc_timeout" || return 1
      is_decimal "$proc_inode" || return 1
      : "$proc_extra"

      proc_local_port=${proc_local#*:}
      if [ "$proc_state" = '0A' ] && [ "$proc_local_port" = '7CF9' ]; then
        operator_listener_count=$((operator_listener_count + 1))
        if [ "$proc_address_width:$proc_local" = '8:0100007F:7CF9' ]; then
          operator_listener_exact=1
        fi
      fi
    done
  } < "$proc_path" 2>/dev/null
}

auth_status=$(doveadm service status auth 2>/dev/null) || exit 1
check_service_status "$auth_status" || exit 1

imap_login_status=$(doveadm service status imap-login 2>/dev/null) || exit 1
check_service_status "$imap_login_status" || exit 1

operator_listener_count=0
operator_listener_exact=0
operator_proc_tcp=${DOVECOT_OPERATOR_PROC_TCP:-/proc/net/tcp}
operator_proc_tcp6=${DOVECOT_OPERATOR_PROC_TCP6:-/proc/net/tcp6}
check_proc_file "$operator_proc_tcp" 8 rem_address || exit 1
check_proc_file "$operator_proc_tcp6" 32 remote_address || exit 1

case "$operator_listener_count:$operator_listener_exact" in
  1:1) exit 0 ;;
  *) exit 1 ;;
esac
