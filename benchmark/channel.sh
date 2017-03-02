#!/bin/bash

OUTPATH=$1

go test -timeout 60m -bench ^BenchmarkChannel.*_1000$ -benchmem pipeline/channel_test.go \
    | grep -e "^Benchmark" \
    | sed "s/[_-]/ /g" \
    | tee -a ~/Dokumente/studium/masterarbeit/thesis/reports/benchmark_raw.txt \
    | awk '{print $2,$3,$6}' \
    | sort -n \
    >> $OUTPATH/benchmark_channel_filters.csv

go test -timeout 60m -bench ^BenchmarkChannel_100_.*$ -benchmem pipeline/channel_test.go \
    | grep -e "^Benchmark" \
    | sed "s/[_-]/ /g" \
    | tee -a ~/Dokumente/studium/masterarbeit/thesis/reports/benchmark_raw.txt \
    | awk '{print $3,$2,$6}' \
    | sort -n \
    >> $OUTPATH/benchmark_channel_packets.csv