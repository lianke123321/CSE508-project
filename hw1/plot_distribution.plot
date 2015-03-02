set title "Packet Length Distribution"
set xlabel "Packet Length (Bytes)"
set ylabel "Fuck (%)"
set autoscale
set out "cdf_pkt_length.eps"
plot "pkt_length.txt" smooth cumulative