#!/bin/bash

OUTPATH=$1
TIMES=$2
LIMIT=$3

go test -timeout $LIMIT -count $TIMES -bench ^BenchmarkCallback.*_1000$ -benchmem pipeline/callback_test.go \
    | grep -e "^Benchmark" \
    | sed "s/[_-]/ /g" \
    | tee -a $OUTPATH/benchmark_raw.txt \
    | awk '{print $2,$3,$6}' \
    | sort -n \
    > $OUTPATH/benchmark_callback_filters_$TIMES.csv

go test -timeout $LIMIT -count $TIMES -bench ^BenchmarkCallback_100_.*$ -benchmem pipeline/callback_test.go \
    | grep -e "^Benchmark" \
    | sed "s/[_-]/ /g" \
    | tee -a $OUTPATH/benchmark_raw.txt \
    | awk '{print $3,$2,$6}' \
    | sort -n \
    > $OUTPATH/benchmark_callback_packets_$TIMES.csv