set datafile separator ","
set title 'IP Packets per Day'
set ylabel 'Packets/day'
set xlabel 'day'
set grid
set term png size 1920,1080
set timefmt "%Y/%m/%d"
set xdata time
set output 'perday.png'
set format x "%Y/%m"
set palette model RGB defined (0 'green', 1 'red')
plot [:][:] 'packetsPerDay_date_20170118.csv' using 1:($2+$4):($2 < 0 ? 1 :  0) with impulses palette
