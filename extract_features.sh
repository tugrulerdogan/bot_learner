#!/bin/bash

#https://github.com/seladb/PcapPlusPlus/tree/master/Examples/PcapSplitter
#./PcapSplitter  -f clean.pcap -o cleanflows/ -m connection

export LC_NUMERIC="en_US.UTF-8"

MAX_TIMEWIN=100000


for file in `find $1 -type f -name '*.pcap'`; do 

    fpart=`tr -cd 0-9 <<< $file`
    fnumber=$(echo $fpart | sed 's/^0*//')
    if (( $fnumber  % $2 == $3)); then 
        buffer=`tshark  -r $file  -e tcp.srcport -e udp.srcport -e tcp.dstport -e udp.dstport -e _ws.col.Protocol   -T fields  | head -1`
        src_port=`echo $buffer | cut -d' ' -f1`
        dst_port=`echo $buffer | cut -d' ' -f2`
        protocol=`echo $buffer | cut -d' ' -f3`
        
        frame_len=`tshark -nr $file -T fields -e frame.len`
        buffer=`echo $frame_len | jq -s 'add/length'`
        APL=`printf '%.*f\n' 2 $buffer`
        
        buffer=`echo $frame_len  | python -c 'from sys import stdin; import numpy as np; nums = [float(i) for i in stdin.read().split()]; print(np.var(nums))'`
        PV=`printf '%.*f\n' 2 $buffer`
        
        buffer=`tcpstat  -r $file  -o '%n %p \n' $MAX_TIMEWIN`
        PX=`echo $buffer | cut -d' ' -f1`
        
        PPS=`echo $buffer | cut -d' ' -f2`
        
        FPS=`echo $frame_len | cut -d' ' -f1`
        
        buffer=`tshark  -r $file -T fields -e frame.time_delta  | jq -s 'add/length'`
        TBP=`printf '%.*f\n' 2 $buffer`
        
        NR=`tshark  -r $file -T fields -e frame.time_delta "tcp.flags!=0x0002" | wc -l`
        
        #TODO calculate fph with hourly data
        FPH=1
    
        #echo "$file $src_port +  $dst_port + $protocol + $APL + $PV + $PX + $PPS + $FPS + $TBP + $NR + $FPH "
        echo "$file $src_port $dst_port $protocol $APL $PV $PX $PPS $FPS $TBP $NR $FPH "
    fi
done 

