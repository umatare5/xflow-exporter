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

TARGET="${1:-all}"
case "$TARGET" in
threats | databases | all) ;;
*)
	# The first argument used to name the merged file. Rejecting a path here
	# rather than treating it as a target keeps an old cron line from
	# selecting nothing and reporting success.
	echo "Usage: $(basename "$0") [threats|databases|all]" >&2
	echo "Paths come from THREAT_FILE, ASN_DATABASE and COUNTRY_DATABASE." >&2
	exit 1
	;;
esac

# Where the exporter reads its enrichment data from. The default is where a
# packaged install puts it, which an unprivileged run cannot create, so the
# three outputs hang off one variable rather than three: a run outside the
# service account moves all of them together.
XFLOW_DATA_DIR="${XFLOW_DATA_DIR:-/var/lib/xflow-exporter}"

THREAT_FILE="${THREAT_FILE:-$XFLOW_DATA_DIR/threat-ips.txt}"
ASN_DATABASE="${ASN_DATABASE:-$XFLOW_DATA_DIR/asn.mmdb}"
COUNTRY_DATABASE="${COUNTRY_DATABASE:-$XFLOW_DATA_DIR/country.mmdb}"

# Addresses that attack inbound, one per line. TweetFeed publishes CSV, whose
# first field is a date, so it is handled separately below.
LISTS=(
	"https://raw.githubusercontent.com/sefinek/Malicious-IP-Addresses/main/lists/main.txt"
	"https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/full-40k.txt"
)

# Malicious destinations -- C2, malware drops and phishing hosts. A hit on the
# destination side of a flow means an inside host reached one of them, which
# the inbound lists above cannot see. The publisher fills a part before it
# opens the next one, so the suffixes are walked until one is absent and the
# size of the part before it says whether that absence is the end or a hole.
SPLIT_LISTS=(
	"https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/main/full-outgoing-ip-%s.txt"
)
SPLIT_SUFFIXES=(aa ab ac ad ae af ag ah ai aj ak)
SPLIT_PART_LINES="${SPLIT_PART_LINES:-131072}"

# The comparisons this feeds are the same shape as the collapse floor below,
# and fail the same way: [ reports a non-numeric comparand as an error rather
# than as false, and an error in an if condition reads as false, which here
# means every 404 is taken for the end of the list.
case "$SPLIT_PART_LINES" in
'' | *[!0-9]*)
	echo "SPLIT_PART_LINES must be a whole number, got '$SPLIT_PART_LINES'" >&2
	exit 1
	;;
esac

# TweetFeed publishes one CSV per day, from which the ip rows are taken.
TWEETFEED_DAYS="${TWEETFEED_DAYS:-7}"

# set -e cannot catch the arithmetic below: a non-numeric value makes the for
# loop's word list empty and the run succeeds having read nothing.
case "$TWEETFEED_DAYS" in
'' | *[!0-9]*)
	echo "TWEETFEED_DAYS must be a whole number, got '$TWEETFEED_DAYS'" >&2
	exit 1
	;;
esac
if [ "$TWEETFEED_DAYS" -lt 1 ]; then
	echo "TWEETFEED_DAYS must be at least 1, got '$TWEETFEED_DAYS'" >&2
	exit 1
fi

# The shape of a line that names an address. It is deliberately loose -- the
# exporter does the real parsing -- and exists to tell a list from an error
# page, which a 200 status cannot.
ADDRESS_SHAPE='^([0-9]{1,3}(\.[0-9]{1,3}){3}|([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f.]{0,39})(/[0-9]{1,3})?$'

# A merged file below this is a collapse rather than a refresh, and writing it
# would replace a working set with a broken one.
MIN_ADDRESSES="${MIN_ADDRESSES:-1000}"

# set -e does not reach the comparison this floor is made of: [ reports a
# non-numeric right-hand side as an error rather than as false, and an error
# in an if condition is read as false, so the collapse guard would be skipped
# by the very value meant to tighten it. A negative number parses and would
# skip it silently.
case "$MIN_ADDRESSES" in
'' | *[!0-9]*)
	echo "MIN_ADDRESSES must be a whole number, got '$MIN_ADDRESSES'" >&2
	exit 1
	;;
esac

# The two databases the exporter reads, as the DB-IP slug and the MaxMind
# edition that name the same data, and the flag each one feeds.
DBIP_URL="${DBIP_URL:-https://download.db-ip.com/free/%s-%s.mmdb.gz}"
MAXMIND_URL="${MAXMIND_URL:-https://download.maxmind.com/app/geoip_download?edition_id=%s&license_key=%s&suffix=tar.gz}"

# A key here switches the databases to MaxMind. Empty takes DB-IP, which
# publishes the lite files without an account.
MAXMIND_LICENSE_KEY="${MAXMIND_LICENSE_KEY:-}"

# A database below this is an error page or a truncated transfer. The smallest
# real file of either publisher is several megabytes.
MIN_DATABASE_BYTES="${MIN_DATABASE_BYTES:-1048576}"

# Numeric for the reason MIN_ADDRESSES gives above.
case "$MIN_DATABASE_BYTES" in
'' | *[!0-9]*)
	echo "MIN_DATABASE_BYTES must be a whole number, got '$MIN_DATABASE_BYTES'" >&2
	exit 1
	;;
esac

# The MaxMind DB format marks its metadata section with these bytes, and the
# reader finds the metadata by searching backwards for them. Nothing else
# tells a database from an error page: both arrive as a file of plausible
# size, and the difference only surfaces when the exporter refuses to start.
DATABASE_MARKER="$(printf '\xab\xcd\xefMaxMind.com')"

workdir="$(mktemp -d)"
tmp=""
trap 'rm -rf "$workdir" ${tmp:+"$tmp"}' EXIT

# Downloads are numbered rather than named after their URL. A name taken from
# the URL can end in something the merge glob does not match, and two feeds
# can share one basename, and both of those lose a list without saying so.
downloads=0
claim_download() {
	downloads=$((downloads + 1))
	out="$(printf '%s/list-%03d.txt' "$workdir" "$downloads")"
}

# fetch retrieves one URL and reports the HTTP status. The status is what
# tells a list that has ended from a list that could not be reached: curl's
# exit code does not, because raw.githubusercontent.com negotiates HTTP/2 and
# answers a 404 with 56, the same code a truncated transfer returns.
fetch() {
	local url="$1" target="$2" code
	code="$(curl -sSL --retry 3 --retry-delay 2 -o "$target" -w '%{http_code}' "$url")" || code="000"
	printf '%s' "$code"
}

# names_addresses reports whether a body looks like a list at all. A 200 is
# not enough: an empty body and an access-denied page both arrive as one, and
# both merge into a file that silently holds nothing.
#
# The body is normalized first, because the merge below normalizes before it
# applies the same shape. Gating the raw bytes made the gate the stricter of
# the two, so a publisher switching to CRLF or appending a comment failed
# every run from then on, over lines the merge would have kept.
names_addresses() {
	# -c rather than -q: -q stops at the first match, and the SIGPIPE that
	# sends upstream would reach pipefail as a body naming no address.
	normalize <"$1" | grep -cE "$ADDRESS_SHAPE" >/dev/null
}

# normalize reduces a body to the one field per line that names an address.
normalize() {
	tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]].*$//'
}

# ensure_writable makes the directory one output needs, before anything is
# fetched.
#
# Up front because the alternative is what it replaces: several hundred
# thousand addresses downloaded, merged, and then thrown away by a mkdir at
# the last step. The run is refused rather than redirected -- the exporter is
# told this path by a flag, and a script that quietly wrote somewhere else
# would leave it reading a file nothing updates, with nothing to say so.
ensure_writable() {
	local path="$1" dir hint
	dir="$(dirname "$path")"
	hint="XFLOW_DATA_DIR=\"\${TMPDIR:-/tmp}/xflow-exporter\" $0 $TARGET"

	if [ ! -d "$dir" ] && ! mkdir -p "$dir" 2>/dev/null; then
		echo "Cannot create $dir, which $(basename "$path") is written to" >&2
		echo "Create it as the account the exporter runs as, or write elsewhere:" >&2
		echo "  $hint" >&2
		return 1
	fi
	if [ ! -w "$dir" ]; then
		echo "$dir is not writable, and $(basename "$path") is written there" >&2
		echo "Take ownership of it as the account the exporter runs as, or write elsewhere:" >&2
		echo "  $hint" >&2
		return 1
	fi
}

# names_database reports whether a body is a MaxMind-format database.
names_database() {
	# -c rather than -q for the SIGPIPE reason names_addresses gives, and -a
	# because grep would otherwise report a binary match rather than count it.
	LC_ALL=C grep -acF "$DATABASE_MARKER" "$1" >/dev/null
}

# fetch_secret retrieves one URL whose query string carries a credential.
# curl reads it from stdin rather than argv, so the key is not on show to
# every other process on the host through ps.
fetch_secret() {
	local url="$1" target="$2" code
	code="$(printf 'url = "%s"\n' "$url" |
		curl -sSL --retry 3 --retry-delay 2 --config - -o "$target" -w '%{http_code}')" || code="000"
	printf '%s' "$code"
}

# month_offset prints the year and month that many months back.
#
# Both spellings pin the day to the first before stepping back: on a 31st,
# BSD date and GNU date each skid into the wrong month.
month_offset() {
	if date -v-1d >/dev/null 2>&1; then
		date -u -v1d -v-"$1"m +%Y-%m
	else
		date -u -d "$(date -u +%Y-%m-01) -$1 month" +%Y-%m
	fi
}

# merge_threat_lists fetches every list and replaces the merged file with
# what they hold between them.
merge_threat_lists() {
	ensure_writable "$THREAT_FILE"

	echo "Fetching the plain lists..."
	for url in "${LISTS[@]}"; do
		claim_download
		code="$(fetch "$url" "$out")"
		if [ "$code" != "200" ]; then
			echo "Failed to fetch $url (HTTP $code)" >&2
			exit 1
		fi
		if ! names_addresses "$out"; then
			echo "Fetched $url but it names no address" >&2
			exit 1
		fi
		echo "  $url"
	done

	echo "Fetching the split lists..."
	for pattern in "${SPLIT_LISTS[@]}"; do
		parts=0
		last_lines=0
		saw_full=0

		for suffix in "${SPLIT_SUFFIXES[@]}"; do
			# Substituting rather than printf'ing, so a percent-encoded URL is
			# not read as a format string.
			url="${pattern/\%s/$suffix}"
			claim_download
			code="$(fetch "$url" "$out")"

			case "$code" in
			200)
				if ! names_addresses "$out"; then
					echo "Fetched $url but it names no address" >&2
					exit 1
				fi
				# awk counts a final line the publisher did not terminate;
				# wc would report a full part as one line short, and a part
				# read as short ends the walk.
				last_lines="$(awk 'END{print NR}' "$out")"
				if [ "$last_lines" -ge "$SPLIT_PART_LINES" ]; then
					saw_full=1
				fi
				parts=$((parts + 1))
				echo "  $url"
				;;
			404)
				# The publisher fills a part before it opens the next one, so a
				# part of exactly the split size has a successor. A 404 after
				# one is a hole, and reading it as the end would drop it and
				# every part behind it while the run still reported success.
				rm -f "$out"
				if [ "$parts" -gt 0 ] && [ "$last_lines" -ge "$SPLIT_PART_LINES" ]; then
					echo "$url is absent though the part before it is full, so that 404 is a gap" >&2
					exit 1
				fi
				break
				;;
			*)
				# Anything else failed to reach a list that does exist. Reading
				# that as the end would overwrite a good file with a short one.
				echo "Failed to fetch $url (HTTP $code)" >&2
				exit 1
				;;
			esac
		done

		if [ "$parts" -eq 0 ]; then
			echo "Failed to fetch any part of ${pattern/\%s/*}" >&2
			exit 1
		fi
		# A full last part has a successor no suffix in the table can name, so
		# the parts past it would be dropped without a word. A short one ends the
		# list, which leaves a table holding exactly as many parts as there are.
		if [ "$parts" -eq "${#SPLIT_SUFFIXES[@]}" ] && [ "$last_lines" -ge "$SPLIT_PART_LINES" ]; then
			echo "Every suffix in SPLIT_SUFFIXES answered for ${pattern/\%s/*} and the last part is full: extend the table" >&2
			exit 1
		fi

		# A multi-part list none of whose parts reaches the split size means the
		# publisher no longer splits at SPLIT_PART_LINES, and the rule above read
		# every 404 as the end without being able to test it.
		if [ "$parts" -gt 1 ] && [ "$saw_full" -eq 0 ]; then
			echo "No part of ${pattern/\%s/*} reached SPLIT_PART_LINES ($SPLIT_PART_LINES): the split size has changed" >&2
			exit 1
		fi
	done

	# TweetFeed is best-effort. It contributes a few dozen addresses against the
	# hundreds of thousands above, so failing the run over it would pin a stale
	# file to protect the smallest feed. Every outcome is reported instead.
	echo "Fetching the last $TWEETFEED_DAYS days of TweetFeed..."
	claim_download
	tweetfeed="$out"
	: >"$tweetfeed"
	days=0
	for offset in $(seq 0 $((10#$TWEETFEED_DAYS - 1))); do
		# BSD date on macOS and GNU date elsewhere spell this differently.
		if date -v-1d >/dev/null 2>&1; then
			day="$(date -u -v-"${offset}"d +%Y%m%d)"
		else
			day="$(date -u -d "-${offset} days" +%Y%m%d)"
		fi

		url="https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/${day:0:4}/${day:0:6}/${day}.csv"
		code="$(fetch "$url" "$workdir/tf-${day}.csv")"
		case "$code" in
		200)
			# date,user,type,value,tags,tweet -- keep the value of the ip rows.
			awk -F, '$3 == "ip" { print $4 }' "$workdir/tf-${day}.csv" >>"$tweetfeed"
			days=$((days + 1))
			;;
		404) ;; # the day's file is not published yet, which is ordinary
		*)
			echo "Could not fetch TweetFeed for $day (HTTP $code)" >&2
			;;
		esac
	done
	echo "  $days of $TWEETFEED_DAYS days"
	if [ "$days" -eq 0 ]; then
		echo "No TweetFeed day could be read, so the merged list is missing that feed" >&2
	fi

	echo "Merging..."
	tmp="$(mktemp "${THREAT_FILE}.XXXXXX")"

	# awk rather than cat: a source whose last line has no newline would otherwise
	# be fused onto the first line of the next, losing both addresses and inventing
	# one that was never published.
	#
	# Keeping only the lines that look like an address drops the comments and the
	# blanks as a side effect, and drops the markup of an error page that reached
	# the merge. grep exits 1 on no match, which pipefail would read as a failure,
	# so an empty result is left to the explicit floor below.
	#
	# LC_ALL=C compares bytes, which is several times faster than a UTF-8
	# collation and is the right comparison for an address anyway.
	awk 1 "$workdir"/list-*.txt |
		normalize |
		{ grep -E "$ADDRESS_SHAPE" || [ "$?" = 1 ]; } |
		LC_ALL=C sort -u >"$tmp"

	count="$(wc -l <"$tmp" | tr -d ' ')"
	if [ "$count" -lt "$MIN_ADDRESSES" ]; then
		echo "Merged only $count addresses, below the floor of $MIN_ADDRESSES: keeping the previous file" >&2
		exit 1
	fi

	# Readable before it is in place, so a reload arriving between the two steps
	# reads the file rather than failing on its mktemp permissions.
	chmod 0644 "$tmp"

	# Replace the output in one step, so a reader never sees a partial file.
	mv "$tmp" "$THREAT_FILE"
	tmp=""

	echo "Wrote $count addresses to $THREAT_FILE"
}

# fetch_dbip retrieves one lite database, falling back a month.
#
# DB-IP stamps the free files with the month, opens the new one partway into
# it and withdraws the old ones later, so a run at the turn of a month finds
# only the previous file and a run that insisted on the current one would
# fail every month for a few days.
fetch_dbip() {
	local slug="$1" target="$2" back month url code
	for back in 0 1; do
		month="$(month_offset "$back")"
		url="${DBIP_URL/\%s/$slug}"
		url="${url/\%s/$month}"

		code="$(fetch "$url" "$target")"
		case "$code" in
		200)
			echo "  $url"
			return 0
			;;
		404) ;;
		*)
			echo "Failed to fetch $url (HTTP $code)" >&2
			return 1
			;;
		esac
	done

	echo "DB-IP publishes $slug for neither of the last two months" >&2
	return 1
}

# fetch_maxmind retrieves one edition with the configured licence key.
fetch_maxmind() {
	local edition="$1" target="$2" url code
	url="${MAXMIND_URL/\%s/$edition}"
	url="${url/\%s/$MAXMIND_LICENSE_KEY}"

	code="$(fetch_secret "$url" "$target")"
	if [ "$code" != "200" ]; then
		# The URL carries the key, so the edition is named instead. A 401
		# here is a key MaxMind did not accept rather than an outage.
		echo "Failed to fetch $edition from MaxMind (HTTP $code)" >&2
		return 1
	fi

	echo "  MaxMind $edition"
}

# fetch_database puts one database in place, whole or not at all.
fetch_database() {
	local slug="$1" edition="$2" target="$3" staged extracted bytes
	staged="$workdir/$slug.mmdb"

	if [ -n "$MAXMIND_LICENSE_KEY" ]; then
		fetch_maxmind "$edition" "$workdir/$slug.tar.gz"

		# The archive holds the database under a directory named for the
		# release date, so the file is found rather than named. Each edition
		# extracts into its own directory: a shared one would let the search
		# return the database fetched before this one.
		mkdir -p "$workdir/$slug.d"
		tar -xzf "$workdir/$slug.tar.gz" -C "$workdir/$slug.d"
		extracted="$(find "$workdir/$slug.d" -type f -name '*.mmdb' | head -1)"
		if [ -z "$extracted" ]; then
			echo "The $edition archive holds no .mmdb file" >&2
			return 1
		fi
		mv "$extracted" "$staged"
	else
		fetch_dbip "$slug" "$workdir/$slug.gz"
		gunzip -c "$workdir/$slug.gz" >"$staged"
	fi

	bytes="$(wc -c <"$staged" | tr -d ' ')"
	if [ "$bytes" -lt "$MIN_DATABASE_BYTES" ]; then
		echo "$slug is $bytes bytes, below the floor of $MIN_DATABASE_BYTES: keeping the previous file" >&2
		return 1
	fi
	if ! names_database "$staged"; then
		echo "$slug carries no MaxMind metadata marker, so it is not a database" >&2
		return 1
	fi

	tmp="$(mktemp "${target}.XXXXXX")"

	# Copied rather than moved: the work directory and the target are rarely
	# on one filesystem, and the rename below has to stay within the target's.
	cat "$staged" >"$tmp"

	# Readable before it is in place, for the reason the merge above gives.
	chmod 0644 "$tmp"
	mv "$tmp" "$target"
	tmp=""

	echo "Wrote $bytes bytes to $target"
}

# fetch_databases puts both databases in place.
fetch_databases() {
	ensure_writable "$ASN_DATABASE"
	ensure_writable "$COUNTRY_DATABASE"

	if [ -n "$MAXMIND_LICENSE_KEY" ]; then
		echo "Fetching the databases from MaxMind..."
	else
		echo "Fetching the databases from DB-IP..."
	fi

	fetch_database dbip-asn-lite GeoLite2-ASN "$ASN_DATABASE"
	fetch_database dbip-country-lite GeoLite2-Country "$COUNTRY_DATABASE"
}

# The lists are the more perishable half, so they go first: a publisher
# outage on the databases still leaves the day's addresses in place, and the
# run reports the failure either way.
case "$TARGET" in
threats) merge_threat_lists ;;
databases) fetch_databases ;;
all)
	merge_threat_lists
	fetch_databases
	;;
esac
