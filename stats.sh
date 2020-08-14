#!/bin/bash

TOTAL_FILES=`find $1 -iname "*.json" | wc -l`
TOTAL_TC_HITS=`find $1 -iname "*.json" -print0 | xargs -0 grep 'trinity_cyber_matches' -rl | wc -l`

echo "Matches per formula ID"
find $1 -iname "*.json" -print0 | xargs -0 grep -h "formula_id" | tr -d ',' | sort | uniq -c | sort -rn
echo ""
echo "Total URLs attempted: $TOTAL_FILES"
echo "Total URLs with content or metadata triggered on by Trinity Cyber: $TOTAL_TC_HITS"
