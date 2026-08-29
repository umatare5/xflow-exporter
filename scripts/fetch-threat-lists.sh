#!/usr/bin/env bash
#
# Fetch the published threat lists and merge them into one file the exporter
# reads with --enrich.threat-file.
#
# The exporter downloads nothing itself. Run this from cron or a CI job, then
# tell the exporter to re-read what it left behind:
#
#   curl -X POST http://localhost:10052/-/reload
#
# or send it a SIGHUP. A run that fails leaves the previous file untouched,
# and the exporter keeps serving the set it already holds.
set -euo pipefail

OUTPUT="${1:-/var/lib/xflow-exporter/threat-ips.txt}"

# Addresses that attack inbound, one per line. TweetFeed publishes CSV, whose
# first field is a date, so it is handled separately below.
LISTS=(
	"https://raw.githubusercontent.com/sefinek/Malicious-IP-Addresses/main/lists/main.txt"
	"https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/full-40k.txt"
)

# Malicious destinations -- C2, malware drops and phishing hosts. A hit on the
# destination side of a flow means an inside host reached one of them, which
# the inbound lists above cannot see. The publisher splits the list at 131072
# entries per file, so the suffixes are walked until one is absent. The list
# ends at the last suffix here, which is 1.4 million addresses of headroom.
SPLIT_LISTS=(
	"https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/main/full-outgoing-ip-%s.txt"
)
SPLIT_SUFFIXES=(aa ab ac ad ae af ag ah ai aj ak)

# TweetFeed publishes one CSV per day, from which the ip rows are taken.
TWEETFEED_DAYS="${TWEETFEED_DAYS:-7}"

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
	code="$(curl -sSL --retry 3 --retry-delay 2 -o "$target" -w '%{http_code}' "$url" 2>/dev/null)" || code="000"
	printf '%s' "$code"
}

echo "Fetching the plain lists..."
for url in "${LISTS[@]}"; do
	claim_download
	code="$(fetch "$url" "$out")"
	if [ "$code" != "200" ]; then
		echo "Failed to fetch $url (HTTP $code)" >&2
		exit 1
	fi
	echo "  $url"
done

echo "Fetching the split lists..."
for pattern in "${SPLIT_LISTS[@]}"; do
	for suffix in "${SPLIT_SUFFIXES[@]}"; do
		# Substituting rather than printf'ing, so a percent-encoded URL is
		# not read as a format string.
		url="${pattern/\%s/$suffix}"
		claim_download
		code="$(fetch "$url" "$out")"
		case "$code" in
		200)
			echo "  $url"
			;;
		404)
			# A suffix the publisher has not reached is the end of the list.
			rm -f "$out"
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
done

echo "Fetching the last $TWEETFEED_DAYS days of TweetFeed..."
claim_download
tweetfeed="$out"
: >"$tweetfeed"
for offset in $(seq 0 $((TWEETFEED_DAYS - 1))); do
	# BSD date on macOS and GNU date elsewhere spell this differently.
	if date -v-1d >/dev/null 2>&1; then
		day="$(date -u -v-"${offset}"d +%Y%m%d)"
	else
		day="$(date -u -d "-${offset} days" +%Y%m%d)"
	fi

	url="https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/${day:0:4}/${day:0:6}/${day}.csv"
	if curl -fsSL --retry 2 -o "$workdir/tf-${day}.csv" "$url" 2>/dev/null; then
		# date,user,type,value,tags,tweet -- keep the value of the ip rows.
		awk -F, '$3 == "ip" { print $4 }' "$workdir/tf-${day}.csv" >>"$tweetfeed"
	fi
done

echo "Merging..."
mkdir -p "$(dirname "$OUTPUT")"
tmp="$(mktemp "${OUTPUT}.XXXXXX")"

# One address per line, comments and blanks dropped, deduplicated. The
# exporter tolerates the rest, but a clean file keeps the load fast. Leading
# whitespace goes before the trailing field does, since cutting first would
# reduce an indented address to nothing and drop it as a blank line.
# LC_ALL=C compares bytes, which is several times faster than a UTF-8
# collation and is the right comparison for an address anyway.
cat "$workdir"/list-*.txt |
	tr -d '\r' |
	sed 's/^[[:space:]]*//; s/[[:space:]].*$//' |
	grep -vE '^[[:space:]]*($|#|;)' |
	LC_ALL=C sort -u >"$tmp"

# Readable before it is in place, so a reload arriving between the two steps
# reads the file rather than failing on its mktemp permissions.
chmod 0644 "$tmp"

# Replace the output in one step, so a reader never sees a partial file.
mv "$tmp" "$OUTPUT"
tmp=""

echo "Wrote $(wc -l <"$OUTPUT" | tr -d ' ') addresses to $OUTPUT"
