#!/usr/bin/env bash
#
# Walk the given devices over SNMP and write the file the exporter reads for
# --enrich.mapping-file: a hostname per device and an ifName per ifIndex.
#
# The exporter speaks no SNMP and holds no credential. Run this from cron or a
# CI job, naming every device that exports flows:
#
#   fetch-device-names.sh 192.0.2.1 192.0.2.2
#
# After a run, tell the exporter to re-read what changed:
#
#   curl -X POST http://localhost:10053/-/reload
#
# or send it a SIGHUP.
#
# SNMP_OPTIONS lands on the command line, where every account on the host can
# read it out of ps. Set it empty and put defCommunity in snmp.conf to keep the
# community off argv.
#
# The output is installed by rename, which is what makes a partial walk safe:
# a run that fails leaves the previous file untouched, and the exporter keeps
# serving the names it holds. It also refuses the file the exporter would --
# a device answering no usable ifName stops the run rather than being written
# out unnamed.
set -euo pipefail

# --- Settings ---------------------------------------------------------------

# Where the exporter reads its data.
XFLOW_DATA_DIR="${XFLOW_DATA_DIR:-/var/lib/xflow-exporter}"

MAPPING_FILE="${MAPPING_FILE:-$XFLOW_DATA_DIR/mapping.yml}"

# Empty leaves the community to snmp.conf, hence - and not :-.
SNMP_OPTIONS="${SNMP_OPTIONS--v2c -c public}"

SYSNAME_OID=".1.3.6.1.2.1.1.5"
IFNAME_OID=".1.3.6.1.2.1.31.1.1.1.1"

# One whole quoted scalar on one line, closing quote and all. Requiring the
# close is what drops the first physical line of a value split over several,
# which would otherwise be written out as an unterminated YAML string.
SCALAR_LINE='^\.[0-9.]+ = STRING: "([^"\\]|\\.)*"$'

# The OID a value is keyed by, for cutting that key back off. Only digits and
# dots may precede the separator, so a value carrying that same separator is
# not where the cut lands.
OID_PREFIX='^\.[0-9.]+'

# net-snmp takes a hostname the exporter would refuse as a key.
ADDRESS_SHAPE='^([0-9]{1,3}(\.[0-9]{1,3}){3}|([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f.]{0,39})$'

# --- Run state --------------------------------------------------------------

# tmp is staged, awaiting its rename.
addresses=()
workdir=""
tmp=""

# --- Reporting --------------------------------------------------------------

# Prints each argument on stderr.
warn() {
	printf '%s\n' "$@" >&2
}

# Stops the run; the previous file is left as is.
abort() {
	warn "$@"
	exit 1
}

# Stops the run over its arguments.
abort_usage() {
	warn "$@"
	exit 2
}

# --- Utilities --------------------------------------------------------------

# Counts lines, without wc's padding.
count_lines() {
	wc -l <"$1" | tr -d ' '
}

# Spells an address as snmp's target.
snmp_target() {
	case "$1" in
	# A bare IPv6 literal reads as Unknown host.
	*:*) printf 'udp6:[%s]' "$1" ;;
	*) printf '%s' "$1" ;;
	esac
}

# Makes the directory the walks land in, and removes it when the run ends.
open_workdir() {
	workdir="$(mktemp -d)"
	trap 'rm -rf "$workdir" ${tmp:+"$tmp"}' EXIT
}

# Replaces the output in one rename.
install_file() {
	tmp="$(mktemp "$2.XXXXXX")"
	cat "$1" >"$tmp"
	# Readable before the rename lands.
	chmod 0644 "$tmp"
	mv "$tmp" "$2"
	tmp=""
}

# --- Predicates -------------------------------------------------------------

# Is the argument an address literal?
is_address_literal() {
	# -c: -q's SIGPIPE would hit pipefail.
	printf '%s' "$1" | grep -cE "$ADDRESS_SHAPE" >/dev/null
}

# Does any line carry a control char?
carries_control_character() {
	grep -q '[[:cntrl:]]' "$1"
}

# --- Validation -------------------------------------------------------------

# Refuses an argument net-snmp would take but the exporter would not.
assert_address_literal() {
	is_address_literal "$1" || abort_usage "$1 is not an address literal" \
		"The file is keyed by the address a device exports from, so a name cannot stand there."
}

# Refuses a device naming no interface.
assert_names_interfaces() {
	(("$2" >= 1)) || abort "$1 answered no interface name this reader can use" \
		"A name carrying a newline, a non-ASCII byte or nothing at all is dropped as it is read."
}

# Refuses a name no label could hold.
assert_printable() {
	! carries_control_character "$2" ||
		abort "$1 answered ${3:-an interface name} carrying a control character"
}

# Refuses an address named more than once.
assert_no_duplicates() {
	local repeated
	repeated="$(printf '%s\n' "$@" | sort | uniq -d)"
	[[ -z "$repeated" ]] || abort "${repeated%%$'\n'*} is named more than once" \
		"The exporter refuses a file that defines one address twice."
}

# Reads the arguments, which name the devices to walk.
parse_addresses() {
	local address
	(($# >= 1)) || abort_usage "Usage: $(basename "$0") ADDRESS..." \
		"The output path comes from MAPPING_FILE."
	for address in "$@"; do
		assert_address_literal "$address"
	done
	assert_no_duplicates "$@"
	addresses=("$@")
}

# --- Output path ------------------------------------------------------------

# Refuses a path no rename can replace.
assert_renameable() {
	[[ ! -e "$1" || -f "$1" ]] ||
		abort "$1 is not a regular file, and the file is installed by renaming onto it"
}

# Makes the directory the output needs.
assert_directory() {
	[[ -d "$1" ]] || mkdir -p "$1" 2>/dev/null ||
		abort "Cannot create $1, which the file is written to"
}

# Refuses an unwritable directory.
assert_writable() {
	[[ -w "$1" ]] || abort "$1 is not writable, and the file is written there"
}

# Settles the directory the output needs, before anything is walked.
ensure_writable() {
	local dir
	dir="$(dirname "$MAPPING_FILE")"
	assert_renameable "$MAPPING_FILE"
	assert_directory "$dir"
	assert_writable "$dir"
}

# --- Walks ------------------------------------------------------------------

# Puts one walk in a file, or stops.
walk_into() {
	local target
	target="$(snmp_target "$1")"
	# -On keeps the numeric OID, -m '' stops the DisplayString hint from
	# printing the value bare, and LC_ALL=C fixes whether a non-ASCII value
	# comes back as text or as hex.
	# shellcheck disable=SC2086 # SNMP_OPTIONS is a word list by design.
	LC_ALL=C snmpwalk $SNMP_OPTIONS -On -m '' "$target" "$2" >"$3" 2>&1 ||
		abort "Failed to walk $2 on $1"
}

# Keeps lines that are a whole scalar.
keep_scalars() {
	# A walk that matched nothing is not an error here; the count is checked.
	grep -E "$SCALAR_LINE" "$1" >"$2" || true
}

# Keeps one device's usable ifNames.
collect_interfaces() {
	local address="$1" kept="$2" count
	walk_into "$address" "$IFNAME_OID" "$kept.raw"
	keep_scalars "$kept.raw" "$kept"
	count="$(count_lines "$kept")"
	assert_names_interfaces "$address" "$count"
	assert_printable "$address" "$kept"
	echo "Read $count interface names from $address"
}

# --- Document ---------------------------------------------------------------

# Appends the hostname, if answered.
append_hostname() {
	local address="$1" out="$2" kept
	kept="$(mktemp "$workdir/sysname-XXXXXX")"
	walk_into "$address" "$SYSNAME_OID" "$kept.raw"
	keep_scalars "$kept.raw" "$kept"
	assert_printable "$address" "$kept" "a system name"
	# net-snmp already quotes and escapes as a YAML double-quoted scalar
	# does, so the value is passed through rather than quoted again.
	sed -E "s/$OID_PREFIX = STRING: /    hostname: /" "$kept" >>"$out"
}

# Appends one device's entry to the document.
append_device() {
	local address="$1" out="$2" kept
	kept="$(mktemp "$workdir/ifname-XXXXXX")"
	collect_interfaces "$address" "$kept"
	printf '  %s:\n' "$address" >>"$out"
	append_hostname "$address" "$out"
	printf '    interfaces:\n' >>"$out"
	sed -E "s/$OID_PREFIX\.([0-9]+) = STRING: /      \1: /" "$kept" >>"$out"
}

# Writes the whole document, which every device has to answer for.
render_document() {
	local address
	printf '# Written by %s. Edits are lost on the next run.\ndevices:\n' \
		"$(basename "$0")" >"$1"
	for address in "${addresses[@]}"; do
		append_device "$address" "$1"
	done
}

# --- Entry point ------------------------------------------------------------

# Walks every device and installs what they answered.
write_mapping() {
	local out="$workdir/mapping.yml"
	render_document "$out"
	install_file "$out" "$MAPPING_FILE"
	echo "Wrote $(count_lines "$MAPPING_FILE") lines to $MAPPING_FILE"
}

main() {
	parse_addresses "$@"
	ensure_writable
	open_workdir
	write_mapping
}

main "$@"
