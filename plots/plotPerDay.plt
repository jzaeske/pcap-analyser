set datafile separator ","
set title 'IP Packets per Day'
set ylabel 'Packets/day'
set xlabel 'day'
set grid
set term png size 1920,1080
set timefmt "%Y/%m"
set xdata time
set output 'perday.png'
set format x "%Y/%m"

filename(n) = sprintf("134.91.78.%d.csv",n)

plot for[i=160:170] filename(i) using 1:3 with lines
