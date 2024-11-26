#!/bin/bash

set -x
OURS=./ft_ssl
THEIRS=openssl

if [ -z "$ITER_COUNT" ]; then
	ITER_COUNT=100
fi

eprintln() {
	echo "$@" >&2
}

randrange() {
	min="$1"
	max="$2"

	python <<EOF
import random
print(random.randrange($min, $max))
EOF
}

rand_list() {
	min="$1"
	max="$2"
	cnt="$3"

	python <<EOF
import random
l = random.sample(range($min, $max + 1), $cnt)
print(" ".join(map(str, l)))
EOF
}

openssl_digest() {
	"$THEIRS" dgst -provider legacy -provider default "-$1"
}

do_digest() {
	bin="$1"
	algo="$2"
	file="$3"

	cat "$file" | "$bin" "$algo" | cut -d ' ' -f 2
}

test_one_digest() {
	algo="$1"
	file="$2"

	ours="$(do_digest "$OURS" "$algo" "$file")"
	theirs="$(do_digest openssl_digest "$algo" "$file")"

	if [ "$ours" != "$theirs" ]; then
		fail_file="fail_$algo.bin"
		cat "$file" > "$fail_file"

		eprintln "KO $fail_file"
		eprintln "expected   $theirs"
		eprintln "got        $ours"
		exit 1
		return 1
	fi
	return 0
}

random_file() {
	len="$1"

	cat /dev/random | head -c "$len"
}

do_one_random_test() {
	algo="$1"
	len="$2"

	file="/tmp/test_$algo.bin"

	random_file "$len" > "$file"

	test_one_digest "$algo" "$file"
}

do_one_string_test() {
	algo="$1"
	string="$2"

	file="/tmp/test_$algo.bin"

	printf "$string" > "$file"

	test_one_digest "$algo" "$file"
}

do_test_algo() {
	algo="$1"

	# emtpy string
	do_one_string_test "$algo" ""

	for len in $(seq 128); do
		do_one_random_test "$algo" $len
	done

	minlen=0
	maxlen=$(echo "2^20" | bc)

	for len in $(rand_list $minlen $maxlen $ITER_COUNT); do
		do_one_random_test "$algo" $len
	done
}

if [ -z "$1" ]; then
	do_test_algo md5 &
	do_test_algo sha224 &
	do_test_algo sha256 &
	do_test_algo sha384 &
	do_test_algo sha512 &
	wait
else
	do_test_algo "$1"
fi
