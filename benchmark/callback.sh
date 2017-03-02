#!/bin/bash

OUTPATH=$1

go test -timeout 60m -bench ^BenchmarkCallback.*_1000$ -benchmem pipeline/callback_test.go \
    | grep -e "^Benchmark" \
    | sed "s/[_-]/ /g" \
    | tee -a ~/Dokumente/studium/masterarbeit/thesis/reports/benchmark_raw.txt \
    | awk '{print $2,$3,$6}' \
    | sort -n \
    >> $OUTPATH/benchmark_callback_filters.csv

go test -timeout 60m -bench ^BenchmarkCallback_100_.*$ -benchmem pipeline/callback_test.go \
    | grep -e "^Benchmark" \
    | sed "s/[_-]/ /g" \
    | tee -a ~/Dokumente/studium/masterarbeit/thesis/reports/benchmark_raw.txt \
    | awk '{print $3,$2,$6}' \
    | sort -n \
    >> $OUTPATH/benchmark_callback_packets.csv