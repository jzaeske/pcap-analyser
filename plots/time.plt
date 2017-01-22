#set title "Data usage over the last 24 hours"
set datafile separator ","
set key autotitle columnhead
set xdata time
set style data lines
set terminal wxt size 350,262 enhanced font 'Verdana,10' persist

inputFile="\"< (head -n 1 /tmp/report && tail -n +2 /tmp/report | sort)\""

set timefmt "%Y/%m/%d"
set xlabel "Time"
set ylabel "Traffic"

set multiplot layout 2,1
plot @inputFile every ::2 using 1:2 w impulses
plot @inputFile every ::2 using 1:4 w impulses