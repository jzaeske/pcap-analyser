#!/bin/bash
# Erzeugt für alle Spalten der Eingabedatei (CSV) eine Ausgabedatei, in welche die jeweils 20 größten Werte der Spalte,
# sowie eine Summenzeile enthalten sind.
# Aufruf: top20.sh input.csv

INPUT_FILE=$1
if [[ ! -n "$INPUT_FILE" ]]; then
  echo "No input file"
  exit 1
fi

IFS=',' read -r -a head <<< `head -n 1 $INPUT_FILE`

sums=$(awk -F"," -v cols="${#head[@]}" '{for(i=2; i<=cols; i++){a[i]+=$i}}END{printf "sums";for(j in a) {printf ",%d", a[j]}}' "$INPUT_FILE")

for i in ${!head[@]}; do
  col="${head[$i]}"
  DIR="${INPUT_FILE/.csv/_top20}"
  mkdir -p "$DIR"
  OUTPUT_FILE="${INPUT_FILE/.csv/_top20\/$col.csv}"
  (head -n 1 $INPUT_FILE && tail -n +3 $INPUT_FILE | sort -t , -nrk"$((i+1))") | head -n 21 > "$OUTPUT_FILE"
  # Sum row for sorting cr
  echo "$sums" >> "$OUTPUT_FILE"
done
