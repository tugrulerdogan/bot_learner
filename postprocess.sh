#!/bin/bash

index=0
declare -a protostring=("uniq" "ESP" "GVSP" "HTTP" "MiNT" "MSMMS" "QUAKE3" "QUAKEWORLD" "ALLJOYN-NS" "DB-LSP-DISC" "DNS" "eDonkey" "ICMP" "LLC" "MDNS" "TCP" "UDP" "M10")

file=$1
cat $file | awk '{ i = 2; for (i; i <= 12; i++){ printf "%s ",$(i)} print ""}' > edited/$file

for proto in "${protostring[@]}"
do
    sed -i "s/$proto/$index/g" edited/$file
    index=$((index + 1))
    echo $index $proto
done
