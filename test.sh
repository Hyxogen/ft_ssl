#!/bin/bash

test_one() {
	timeout "$1" ./test_digest.sh "$2"
	RESULT="$?"
	if [ "$RESULT" -eq 124 ]; then
		return 0
	elif [ "$RESULT" -ne 0 ]; then
		echo "a test failed: $RESULT" >&2
		exit 1;
	fi
}

DURATION=5s

test_one "$DURATION" md5 &
test_one "$DURATION" sha256 &
test_one "$DURATION" sha384 &
test_one "$DURATION" sha512 &
test_one "$DURATION" whirlpool &
wait
