#!/usr/bin/env bash
#
# Fetch the enrichment data the exporter reads off local disk: the published
# threat lists merged into one file for --enrich.threat-file, and the
# MaxMind-format databases for --enrich.asn-database and --enrich.country-database.
#
# The exporter downloads nothing itself and holds no credential. Run this from
# cron or a CI job:
#
#   fetch-enrichment-data.sh              # both
#   fetch-enrichment-data.sh threats      # the merged list alone
#   fetch-enrichment-data.sh databases    # the two databases alone
#
# After any run, tell the exporter to re-read what changed:
#
#   curl -X POST http://localhost:10052/-/reload
#
# or send it a SIGHUP. One reload covers the lists and the databases alike.
#
# Every output is installed by rename, which is what makes that safe: the
# exporter memory-maps the databases, so replacing one in place would change
# the bytes under a reader that is serving lookups. A run that fails leaves
# the previous files untouched, and the exporter keeps serving what it holds.
set -euo pipefail

# --- Settings ---------------------------------------------------------------

# Where the exporter reads its data.
XFLOW_DATA_DIR="${XFLOW_DATA_DIR:-/var/lib/xflow-exporter}"

THREAT_FILE="${THREAT_FILE:-$XFLOW_DATA_DIR/threat-ips.txt}"
ASN_DATABASE="${ASN_DATABASE:-$XFLOW_DATA_DIR/asn.mmdb}"
COUNTRY_DATABASE="${COUNTRY_DATABASE:-$XFLOW_DATA_DIR/country.mmdb}"

# Inbound attackers, one per line.
LISTS=(
	"https://raw.githubusercontent.com/sefinek/Malicious-IP-Addresses/main/lists/main.txt"
	"https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/full-40k.txt"
)

# Malicious destinations, in parts.
SPLIT_LISTS=(
	"https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/main/full-outgoing-ip-%s.txt"
)
SPLIT_SUFFIXES=(aa ab ac ad ae af ag ah ai aj ak)
# A part this long has a successor.
SPLIT_PART_LINES="${SPLIT_PART_LINES:-131072}"

# One CSV per day; ip rows are kept.
TWEETFEED_URL="https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/%s/%s/%s.csv"
TWEETFEED_DAYS="${TWEETFEED_DAYS:-7}"

# Tells a list from an error page.
ADDRESS_SHAPE='^([0-9]{1,3}(\.[0-9]{1,3}){3}|([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f.]{0,39})(/[0-9]{1,3})?$'

# Below this a merge is a collapse.
MIN_ADDRESSES="${MIN_ADDRESSES:-1000}"

# The two publishers of the same data.
DBIP_URL="${DBIP_URL:-https://download.db-ip.com/free/%s-%s.mmdb.gz}"
MAXMIND_URL="${MAXMIND_URL:-https://download.maxmind.com/app/geoip_download?edition_id=%s&license_key=%s&suffix=tar.gz}"

# A key here switches to MaxMind.
MAXMIND_LICENSE_KEY="${MAXMIND_LICENSE_KEY:-}"

# Below this it is an error page.
MIN_DATABASE_BYTES="${MIN_DATABASE_BYTES:-1048576}"

# What marks a MaxMind DB's metadata.
DATABASE_MARKER="$(printf '\xab\xcd\xefMaxMind.com')"

# --- Run state --------------------------------------------------------------

# tmp is staged, awaiting its rename.
target="all"
workdir=""
tmp=""

# What one split-list walk has seen.
split_parts=0
split_last_lines=0
split_saw_full=0

# --- Reporting --------------------------------------------------------------

# Prints each argument on stderr.
warn() {
	printf '%s\n' "$@" >&2
}

# Stops the run; outputs are left as is.
abort() {
	warn "$@"
	exit 1
}

# --- Utilities --------------------------------------------------------------

# Substitutes each argument for one %s.
fill_template() {
	local out="$1" value
	shift
	for value in "$@"; do
		out="${out/\%s/$value}"
	done
	printf '%s' "$out"
}

# Counts lines, without wc's padding.
count_lines() {
	wc -l <"$1" | tr -d ' '
}

# Counts bytes, without wc's padding.
count_bytes() {
	wc -c <"$1" | tr -d ' '
}

# Does date take BSD -v, not GNU -d?
has_bsd_date() {
	date -v-1d >/dev/null 2>&1
}

# Prints the year-month N months back.
month_offset() {
	if has_bsd_date; then
		date -u -v1d -v-"$1"m +%Y-%m
	else
		date -u -d "$(date -u +%Y-%m-01) -$1 month" +%Y-%m
	fi
}

# Prints the day N days back.
day_offset() {
	if has_bsd_date; then
		date -u -v-"$1"d +%Y%m%d
	else
		date -u -d "-$1 days" +%Y%m%d
	fi
}

# --- Predicates -------------------------------------------------------------

# Reduces a body to one field per line.
normalize() {
	tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]].*$//'
}

# Does a body name any address at all?
names_addresses() {
	# -c: -q's SIGPIPE would hit pipefail.
	normalize <"$1" | grep -cE "$ADDRESS_SHAPE" >/dev/null
}

# Is a body a MaxMind-format database?
names_database() {
	# -a counts; -c avoids -q's SIGPIPE.
	LC_ALL=C grep -acF "$DATABASE_MARKER" "$1" >/dev/null
}

# Did a part reach the split size?
is_full_part() {
	[ "$1" -ge "$SPLIT_PART_LINES" ]
}

# Does the licence key select MaxMind?
uses_maxmind() {
	[ -n "$MAXMIND_LICENSE_KEY" ]
}

# --- Validation -------------------------------------------------------------

# Refuses a setting that is not whole.
assert_whole_number() {
	case "$2" in
	'' | *[!0-9]*) abort "$1 must be a whole number, got '$2'" ;;
	esac
}

# Refuses a setting below one.
assert_counting_number() {
	assert_whole_number "$1" "$2"
	[ "$2" -ge 1 ] || abort "$1 must be at least 1, got '$2'"
}

# Refuses a setting no comparison could use, before anything is fetched.
validate_settings() {
	assert_whole_number SPLIT_PART_LINES "$SPLIT_PART_LINES"
	assert_counting_number TWEETFEED_DAYS "$TWEETFEED_DAYS"
	assert_whole_number MIN_ADDRESSES "$MIN_ADDRESSES"
	assert_whole_number MIN_DATABASE_BYTES "$MIN_DATABASE_BYTES"
}

# Reads the one argument, which selects what a run fetches.
parse_target() {
	case "$1" in
	threats | databases | all) target="$1" ;;
	# A path here was once the merged file.
	*) abort "Usage: $(basename "$0") [threats|databases|all]" \
		"Paths come from THREAT_FILE, ASN_DATABASE and COUNTRY_DATABASE." ;;
	esac
}

# --- Output paths -----------------------------------------------------------

# Reports an unusable output path.
refuse_output() {
	abort "$1" "$2" "  XFLOW_DATA_DIR=\"\${TMPDIR:-/tmp}/xflow-exporter\" $0 $target"
}

# Refuses a path no rename can replace.
assert_renameable() {
	if [ -e "$1" ] && [ ! -f "$1" ]; then
		refuse_output "$1 is not a regular file, and $2 is installed by renaming onto it" \
			"Remove it, or write elsewhere:"
	fi
}

# Makes the directory an output needs.
assert_directory() {
	if [ ! -d "$1" ] && ! mkdir -p "$1" 2>/dev/null; then
		refuse_output "Cannot create $1, which $2 is written to" \
			"Create it as the account the exporter runs as, or write elsewhere:"
	fi
}

# Refuses an unwritable directory.
assert_writable() {
	[ -w "$1" ] || refuse_output "$1 is not writable, and $2 is written there" \
		"Take ownership of it as the account the exporter runs as, or write elsewhere:"
}

# Settles the directory one output needs, before anything is fetched.
ensure_writable() {
	local name dir
	name="$(basename "$1")"
	dir="$(dirname "$1")"
	assert_renameable "$1" "$name"
	assert_directory "$dir" "$name"
	assert_writable "$dir" "$name"
}

# --- Transfers --------------------------------------------------------------

# Makes the directory downloads land in, and removes it when the run ends.
open_workdir() {
	workdir="$(mktemp -d)"
	trap 'rm -rf "$workdir" ${tmp:+"$tmp"}' EXIT
}

# Retrieves a URL, printing its status.
fetch() {
	local code
	code="$(printf 'url = "%s"\n' "$1" |
		curl -sSL --retry 3 --retry-delay 2 --config - -o "$2" -w '%{http_code}')" || code="000"
	printf '%s' "$code"
}

# Refuses a status other than 200.
assert_http_ok() {
	[ "$2" = "200" ] || abort "Failed to fetch $1 (HTTP $2)"
}

# Refuses a body naming no address.
assert_names_addresses() {
	names_addresses "$2" || abort "Fetched $1 but it names no address"
}

# Names an empty file for one body.
new_download_path() {
	mktemp "$workdir/list-XXXXXX"
}

# Replaces an output in one rename.
install_file() {
	tmp="$(mktemp "$2.XXXXXX")"
	cat "$1" >"$tmp"
	# Readable before the rename lands.
	chmod 0644 "$tmp"
	mv "$tmp" "$2"
	tmp=""
}

# --- Threat lists -----------------------------------------------------------

# Retrieves one list held in one body.
fetch_plain_list() {
	local path code
	path="$(new_download_path)"
	code="$(fetch "$1" "$path")"
	assert_http_ok "$1" "$code"
	assert_names_addresses "$1" "$path"
	echo "  $1"
}

# Retrieves every list published in one piece.
fetch_plain_lists() {
	local url
	echo "Fetching the plain lists..."
	for url in "${LISTS[@]}"; do
		fetch_plain_list "$url"
	done
}

# Records one part that answered.
accept_split_part() {
	assert_names_addresses "$1" "$2"
	# awk counts an unterminated last line.
	split_last_lines="$(awk 'END{print NR}' "$2")"
	if is_full_part "$split_last_lines"; then
		split_saw_full=1
	fi
	split_parts=$((split_parts + 1))
	echo "  $1"
}

# Ends the walk, refusing a gap.
end_split_walk() {
	rm -f "$2"
	if [ "$split_parts" -gt 0 ] && is_full_part "$split_last_lines"; then
		abort "$1 is absent though the part before it is full, so that 404 is a gap"
	fi
	return 1
}

# Fetches one part; false ends the walk.
take_split_part() {
	local url="$1" path code
	path="$(new_download_path)"
	code="$(fetch "$url" "$path")"
	case "$code" in
	200) accept_split_part "$url" "$path" ;;
	404) end_split_walk "$url" "$path" ;;
	*) assert_http_ok "$url" "$code" ;;
	esac
}

# Refuses a pattern answering nothing.
assert_parts_fetched() {
	[ "$split_parts" -gt 0 ] || abort "Failed to fetch any part of ${1/\%s/*}"
}

# Refuses an end the split size denies.
assert_split_size_holds() {
	local name="${1/\%s/*}"
	# A full last part has a successor.
	if [ "$split_parts" -eq "${#SPLIT_SUFFIXES[@]}" ] && is_full_part "$split_last_lines"; then
		abort "Every suffix in SPLIT_SUFFIXES answered for $name and the last part is full: extend the table"
	fi
	# No full part: the split size changed.
	if [ "$split_parts" -gt 1 ] && [ "$split_saw_full" -eq 0 ]; then
		abort "No part of $name reached SPLIT_PART_LINES ($SPLIT_PART_LINES): the split size has changed"
	fi
}

# Forgets the previously walked list.
reset_split_walk() {
	split_parts=0
	split_last_lines=0
	split_saw_full=0
}

# Walks a pattern to its last part.
fetch_split_list() {
	local pattern="$1" suffix
	reset_split_walk
	for suffix in "${SPLIT_SUFFIXES[@]}"; do
		take_split_part "$(fill_template "$pattern" "$suffix")" || break
	done
	assert_parts_fetched "$pattern"
	assert_split_size_holds "$pattern"
}

# Retrieves every list published in parts.
fetch_split_lists() {
	local pattern
	echo "Fetching the split lists..."
	for pattern in "${SPLIT_LISTS[@]}"; do
		fetch_split_list "$pattern"
	done
}

# Appends one day; false if unread.
take_tweetfeed_day() {
	local day="$1" csv code
	csv="$workdir/tf-$day.csv"
	code="$(fetch "$(fill_template "$TWEETFEED_URL" "${day:0:4}" "${day:0:6}" "$day")" "$csv")"
	# An unpublished day is ordinary.
	[ "$code" != "404" ] || return 1
	warn_unreadable_day "$day" "$code" || return 1
	# date,user,type,value,tags,tweet
	awk -F, '$3 == "ip" { print $4 }' "$csv" >>"$2"
}

# Reports a day that could not be read.
warn_unreadable_day() {
	[ "$2" != "200" ] || return 0
	warn "Could not fetch TweetFeed for $1 (HTTP $2)"
	return 1
}

# Says how much of the feed was read.
report_tweetfeed_days() {
	echo "  $1 of $TWEETFEED_DAYS days"
	[ "$1" -eq 0 ] || return 0
	warn "No TweetFeed day could be read, so the merged list is missing that feed"
}

# Retrieves the last TWEETFEED_DAYS days of the feed, best-effort.
fetch_tweetfeed() {
	local path offset days=0
	echo "Fetching the last $TWEETFEED_DAYS days of TweetFeed..."
	path="$(new_download_path)"
	for offset in $(seq 0 $((10#$TWEETFEED_DAYS - 1))); do
		take_tweetfeed_day "$(day_offset "$offset")" "$path" && days=$((days + 1))
	done
	report_tweetfeed_days "$days"
}

# Sorts every body into one list.
merge_downloads() {
	# awk 1 keeps an unterminated last line.
	awk 1 "$workdir"/list-* |
		normalize |
		# grep exits 1 on no match.
		{ grep -E "$ADDRESS_SHAPE" || [ "$?" = 1 ]; } |
		LC_ALL=C sort -u >"$1"
}

# Refuses a merge that collapsed.
assert_enough_addresses() {
	[ "$1" -ge "$MIN_ADDRESSES" ] ||
		abort "Merged only $1 addresses, below the floor of $MIN_ADDRESSES: keeping the previous file"
}

# Writes what the fetched lists hold between them.
install_threat_file() {
	local merged="$workdir/merged.txt" count
	echo "Merging..."
	merge_downloads "$merged"
	count="$(count_lines "$merged")"
	assert_enough_addresses "$count"
	install_file "$merged" "$THREAT_FILE"
	echo "Wrote $count addresses to $THREAT_FILE"
}

# Replaces the merged file with what every list holds between them.
merge_threat_lists() {
	ensure_writable "$THREAT_FILE"
	fetch_plain_lists
	fetch_split_lists
	fetch_tweetfeed
	install_threat_file
}

# --- Databases --------------------------------------------------------------

# Fetches a month; false if absent.
try_dbip_month() {
	local url code
	url="$(fill_template "$DBIP_URL" "$1" "$(month_offset "$3")")"
	code="$(fetch "$url" "$2")"
	[ "$code" != "404" ] || return 1
	assert_http_ok "$url" "$code"
	echo "  $url"
}

# Tries this month, then the one before.
fetch_dbip() {
	local back
	for back in 0 1; do
		try_dbip_month "$1" "$2" "$back" && return 0
	done
	abort "DB-IP publishes $1 for neither of the last two months"
}

# Unpacks what DB-IP publishes gzipped.
stage_dbip() {
	fetch_dbip "$1" "$workdir/$1.gz"
	gunzip -c "$workdir/$1.gz" >"$2"
}

# Retrieves one edition with the key.
fetch_maxmind() {
	local url code
	url="$(fill_template "$MAXMIND_URL" "$1" "$MAXMIND_LICENSE_KEY")"
	code="$(fetch "$url" "$2")"
	# The URL carries the key.
	[ "$code" = "200" ] || abort "Failed to fetch $1 from MaxMind (HTTP $code)"
	echo "  MaxMind $1"
}

# Extracts the .mmdb from the archive.
stage_maxmind() {
	local dir="$workdir/$1.d" extracted
	fetch_maxmind "$1" "$dir.tar.gz"
	mkdir -p "$dir"
	tar -xzf "$dir.tar.gz" -C "$dir"
	extracted="$(find "$dir" -type f -name '*.mmdb' | head -1)"
	[ -n "$extracted" ] || abort "The $1 archive holds no .mmdb file"
	mv "$extracted" "$2"
}

# Stages from the selected publisher.
stage_database() {
	if uses_maxmind; then
		stage_maxmind "$2" "$3"
	else
		stage_dbip "$1" "$3"
	fi
}

# Refuses a body that is not a database.
assert_database() {
	[ "$3" -ge "$MIN_DATABASE_BYTES" ] ||
		abort "$1 is $3 bytes, below the floor of $MIN_DATABASE_BYTES: keeping the previous file"
	names_database "$2" || abort "$1 carries no MaxMind metadata marker, so it is not a database"
}

# Puts one database in place, whole or not at all.
fetch_database() {
	local slug="$1" edition="$2" target_path="$3" staged bytes
	staged="$workdir/$slug.mmdb"
	stage_database "$slug" "$edition" "$staged"
	bytes="$(count_bytes "$staged")"
	assert_database "$slug" "$staged" "$bytes"
	install_file "$staged" "$target_path"
	echo "Wrote $bytes bytes to $target_path"
}

# Names the publisher the licence key selects.
announce_publisher() {
	if uses_maxmind; then
		echo "Fetching the databases from MaxMind..."
	else
		echo "Fetching the databases from DB-IP..."
	fi
}

# Puts both databases in place.
fetch_databases() {
	ensure_writable "$ASN_DATABASE"
	ensure_writable "$COUNTRY_DATABASE"
	announce_publisher
	fetch_database dbip-asn-lite GeoLite2-ASN "$ASN_DATABASE"
	fetch_database dbip-country-lite GeoLite2-Country "$COUNTRY_DATABASE"
}

# --- Entry point ------------------------------------------------------------

# Fetches what the argument selected, the more perishable lists first.
run_target() {
	case "$target" in
	threats) merge_threat_lists ;;
	databases) fetch_databases ;;
	all)
		merge_threat_lists
		fetch_databases
		;;
	esac
}

main() {
	parse_target "${1:-all}"
	validate_settings
	open_workdir
	run_target
}

main "$@"
