#!/bin/bash

SCRIPTPATH=$( cd $(dirname $0) ; pwd -P )
TRACE_GREPPED="cache"

# set by configuration file
BUGALIZER_SIPV=""
BUGALIZER_PRODUCTION_CSS="$SCRIPTPATH/production_css.csv"
BUGALIZER_CONFIG_FILE="$SCRIPTPATH/bugalyzer.conf"
DEBUG_MODE=0

create_config ()
{
    if ! [[ -f $BUGALIZER_CONFIG_FILE ]]; then
        touch $BUGALIZER_CONFIG_FILE
        echo "BUGALIZER_SIPV="  >> $BUGALIZER_CONFIG_FILE
        echo "DEBUG_MODE=0"     >> $BUGALIZER_CONFIG_FILE
        echo "Configuartion file created"
    fi
}

load_config_property ()
{
    local prop=$1
    grep $prop $BUGALIZER_CONFIG_FILE | awk -F'=' '{print $2}'
}

load_config ()
{
    if ! [[ -f $BUGALIZER_CONFIG_FILE ]]; then
        create_config
    fi

    BUGALIZER_SIPV=$(load_config_property "BUGALIZER_SIPV")
    #BUGALIZER_PRODUCTION_CSS=$(load_config_property "BUGALIZER_PRODUCTION_CSS")
    DEBUG_MODE=$(load_config_property "DEBUG_MODE")

    [[ -z $BUGALIZER_SIPV ]] || [[ $BUGALIZER_SIPV == "" ]] && error_exit "SIP viewer not configured in bugalyzer.conf"
    #[[ -z $BUGALIZER_PRODUCTION_CSS ]] || [[ $BUGALIZER_PRODUCTION_CSS == "" ]] && error_exit "Production CSS table not configured in bugalyzer.conf"
    debug "Debug mode ON"
}

# in order not to grep for inbound call ID many times, the result is cached in a file and deleted upon exit
grep_inbound ()
{
    local trace_log=$1
    local inbound=$2

    local grepped="$TRACE_GREPPED"_"$inbound"
    if [[ ! -f $grepped ]]; then
        grep 00$inbound $trace_log > $grepped
    fi
    cat $grepped
}

get_outbound_by_inbound ()
{
    local trace_log=$1
    local inbound=$2

    grep_inbound $trace_log $inbound | grep play | grep OUTBOUND | head -1 | awk -F'|' '{ print $7 }'
}

get_caller_by_inbound ()
{
    local trace_log=$1
    local inbound=$2

    grep_inbound $trace_log $inbound | grep "CallState" | head -1 | awk -F'|' '{ print $8 }'
}

get_callee_by_inbound ()
{
    local trace_log=$1
    local inbound=$2

    grep_inbound $trace_log $inbound | grep "CallState" | head -1 | awk -F'|' '{ print $9 }'
}

get_inbound_by_outbound ()
{
    local trace_log=$1
    local outbound=$2
    grep 00$outbound $trace_log | grep play | grep INBOUND | head -1 | awk -F'|' '{ print $7 }'
}

get_sip_id_by_inbound ()
{
    local trace_log=$1
    local inbound=$2

    grep_inbound $trace_log $inbound | grep call-ID | head -1 | awk -F'|' '{ print $11 }' | awk '{ print $5 }' | sed 's/.$//'
}

get_next_sip_id_by_inbound ()
{
    local trace_log=$1
    local inbound=$2

    local callmgrtag=`grep_inbound $trace_log $inbound | grep play | grep OUTBOUND | head -1 | awk -F'|' '{ print $8 }' | awk -F';' '{ print $2 }'`
    [[ ! -z $callmgrtag ]] && grep "From.*$callmgrtag" $trace_log -B2 | head -1 | awk '{print $2}'
}

get_next_sip_id_by_sip_id ()
{
    local trace_log=$1
    local sipID=$2
    local inbound=`get_inbound_by_sip_id $trace_log $sipID`
    get_next_sip_id_by_inbound ${inbound: -5} $trace_log
    #local callmgrtag=`grep 00${inbound: -5} $trace_log | grep play | grep OUTBOUND | head -1 | awk -F'|' '{ print $8 }' | awk -F';' '{ print $2 }'`
    #[[ ! -z $callmgrtag ]] && grep "From.*$callmgrtag" $trace_log -B2 | head -1 | awk '{print $2}'
}

get_inbound_by_sip_id ()
{
    local trace_log=$1
    local sipID=$2
    local inbound=`grep ${sipID:0:-1} $trace_log | grep call-ID | head -1 | awk -F'|' '{ print $7 }'`
    echo $inbound
}

get_outbound_by_sip_id ()
{
    local trace_log=$1
    local sipID=$2

    local outbound=`get_outbound_by_inbound $trace_log ${inbound: -5}`
    echo $outbound
}

get_caller_ip_by_inbound ()
{
    local trace_log=$1
    local inbound=$2

    local call_id=$(get_sip_id_by_inbound $trace_log ${inbound: -5})
    if $(is_leg_web $inbound); then
        grep $call_id $trace_log | head -1 | awk -F'|' '{print $6}' | sed -e 's/^\w*: \ *//' | jq -r '.ip'
    elif $(is_leg_sip $inbound); then
        grep $call_id $trace_log | grep "SIPManager.*REQ.*INVITE.*received" | head -1 | awk -F'|' '{print $15}' | awk '{print $1}'
    else
        echo "TBD"
    fi

}

get_callee_ip_by_sip_id ()
{
    local trace_log=$1
    local sipID=$2

    echo "TBD"
}

get_caller_name_by_inbound ()
{
    local trace_log=$1
    local inbound=$2

    local call_id=$(get_sip_id_by_inbound $trace_log ${inbound: -5})
    if [[ ${inbound:0:7} == "WEB_WAN" ]]; then
        grep $call_id $trace_log | head -1 | awk -F'|' '{print $6}' | sed -e 's/^\w*: \ *//' | jq -r '.payload.args.displayName'
    else
        local name=`grep $call_id $trace_log -A20 | head -20 | grep From | awk '{printf "%s %s\n", $2, $3}'`
        echo ${name:1:-1}   # remove quotes from beginning and end
    fi
}

is_leg_sip ()
{
    local leg=$1

    [[ ${leg:0:4} == "SIP_" ]]
}

is_leg_web ()
{
    local leg=$1

    [[ ${leg:0:7} == "WEB_WAN" ]]
}

get_callee_name_by_inbound ()
{
    local trace_log=$1
    local inbound=$2

    grep_inbound $trace_log ${inbound: -5} | grep "CallState: PROCEEDING" | awk -F'|' '{print $9}' | awk -F'@' '{print $1}' | awk -F':' '{printf "%s:%s\n", $2, $3}'
}

get_caller_client_by_inbound ()
{
    local trace_log=$1
    local inbound=$2
    local caller_ext=$3

    local call_id=$(get_sip_id_by_inbound $trace_log ${inbound: -5})
    if $(is_leg_web $inbound); then
        local line=`grep "WebManager" $trace_log | grep "register" | grep $caller_ext | head -1 | awk -F'|' '{print $6}'`
        local user_agent=`echo ${line:19} | jq -r '.payload.args.userAgent'`
        if [[ $user_agent == *Electron* ]]; then
            # desktop client
            echo "$user_agent" | awk '{printf "%s %s\n", $10, $12}'
        else
            # web client
            echo "$user_agent" | awk '{printf "%s\n", $10}'
        fi
    elif $(is_leg_sip $inbound); then
        local client=`grep $call_id $trace_log -A30 | head -30 | grep User-Agent`
        echo ${client:12}   # remove "User-Agent: "
    else
        echo "TBD"
    fi
}

get_callee_client_by_inbound ()
{
    local trace_log=$1
    local inbound=$2

    #grep_inbound $trace_log $inbound | grep "CallState: PROCEEDING" | awk -F'|' '{print $9}' | awk -F'@' '{print $1}' | awk -F':' '{printf "%s:%s\n", $2, $3}'
    echo "TBD"
}

get_node_version ()
{
    local trace_log=$1
    local call_id_ib=$2
    local call_id_ob=$3
    local inbound=$4
    local outbound=$5

    local user_agent=""

    if $(is_leg_sip $inbound); then
        user_agent=`grep "INVITE_100|${call_id_ib:0:12}" $trace_log -A30 | head -30 | grep User-Agent | head -1`
        echo ${user_agent:12}
    elif $(is_leg_web $inbound); then
        if $(is_leg_sip $outbound); then
            user_agent=`grep "INVITE|${call_id_ob:0:12}" $trace_log -A30 | head -30 | grep User-Agent | head -1`
            echo ${user_agent:12}
        else
            echo "N/A"
        fi
    else
        echo "N/A"
    fi
}

get_all_call_handlers_ids ()
{
    local trace_log=$1

    grep "|CallTrace" $trace_log | awk -F'|' '{ print $7 }' | awk '!a[$0]++'
}

get_all_call_handlers_ids_of_caller ()
{
    local trace_log=$1
    local caller_extension=$2
    local time=$3

    if [[ ! -z $time ]]; then
        grep $caller_extension $trace_log | grep INBOUND | grep "CallState\: PROCEEDING" | awk -F'|' '{ printf "%s  %s\n",$1, $7 }' | tr ' ' '-'
    else
        grep $caller_extension $trace_log | grep INBOUND | grep "CallState\: PROCEEDING" | awk -F'|' '{ print $7 }'
    fi
    #grep $caller_extension $trace_log | grep "SIP_" | grep "CallState\: RINGBACK" | awk -F'|' '{ print $7 }'
}

# In a scenario when there's an OUTBOUND call to an MP
get_mp_by_outbound () 
{
    local transactions_log=$1
    local outbound=$2

    grep $outbound $transactions_log | grep "callState\":\"PROCEEDING"
}

usage()
{
    echo "Usage: `basename $0` [--option1] [--option2] [--option3] [--option4]"
}

error_exit ()
{
    echo "$1. Exiting"
    exit
}

warn ()
{
    echo "Warning! $1. Continuing"
}

debug () { if [[ $DEBUG_MODE == 1 ]]; then echo "$@"; fi }

# legend for colums numbers in CallStats.log
# outer columns
    STATS_AUDIO_TX=3
    STATS_AUDIO_RX=4
    STATS_VIDEO_TX=6
    STATS_VIDEO_RX=7
    STATS_PRESE_TX=9
    STATS_PRESE_RX=10
# inner columns
    STATS_BW=1
    STATS_PACKETS=2
    STATS_LOSS=3

get_one ()
{
    local inbound=$1
    local folder1=$2 # folder of node 1
    local folder2=$3 # folder of node 1
    local time=$4
    local caller=$5
    local trace1=$6
    local trace2=$7
    local stats1=$8
    local stats2=$9

    echo "=========================================================================="
    echo "Analysing for inbound call $inbound"
    echo "=========================================================================="

    # searching node 1
    ib=${inbound: -5}
    local outbound=$(get_outbound_by_inbound $trace1 $ib)
    local caller1=$(get_caller_by_inbound $trace1 $ib)
    local callee=$(get_callee_by_inbound $trace1 $ib)
    local sip=$(get_sip_id_by_inbound $trace1 $ib)
    local sip_next=$(get_next_sip_id_by_inbound $trace1 $ib)

    # searching node 2
    local inbound2=$(get_inbound_by_sip_id $trace2 $sip_next)
    ib2=${inbound2: -5}
    local caller2=$(get_caller_by_inbound $trace2 $ib2)
    local callee2=$(get_callee_by_inbound $trace2 $ib2)
    local sip2=$(get_sip_id_by_inbound $trace2 $ib2)
    local outbound2=$(get_outbound_by_inbound $trace2 $ib2)
    local sip_next2=$(get_next_sip_id_by_inbound $trace2 $ib2)

    local caller_ip=$(get_caller_ip_by_inbound $trace1 $inbound)
    local callee_ip=$(get_callee_ip_by_sip_id $trace1 $sip)
    local caller_name=$(get_caller_name_by_inbound $trace1 $inbound)
    local callee_name=$(get_callee_name_by_inbound $trace2 $inbound2)
    local caller_client=$(get_caller_client_by_inbound $trace1 $inbound $caller)
    local callee_client=$(get_callee_client_by_inbound $trace2 $inbound2)
    
    local node1_version=$(get_node_version "$trace1" "$sip"      "$sip_next"  "$inbound"  "$outbound")
    local node2_version=$(get_node_version "$trace2" "$sip_next" "$sip_next2" "$inbound2" "$outbound2")

    draw_text_general "$caller_ip" "$callee_ip" "$caller_name" "$callee_name" "$caller_client" "$callee_client"
    draw_text_node "$folder1" "$inbound" "$outbound" "$caller" "$callee" "$sip" "$sip_next" "$node1_version"
    draw_text_node "$folder2" "$inbound2" "$outbound2" "$caller2" "$callee2" "$sip2" "$sip_next2" "$node2_version"

    # find nodes IPs and names
    local node1_id=${folder1:0:4}
    local node2_id=${folder2:0:4}
    local node1_ip_ext=`grep "$node1_id" "$BUGALIZER_PRODUCTION_CSS" | awk -F',' '{print $4}'`
    local node1_ip_int=`grep "$node1_id" "$BUGALIZER_PRODUCTION_CSS" | awk -F',' '{print $5}'`
    local node2_ip_ext=`grep "$node2_id" "$BUGALIZER_PRODUCTION_CSS" | awk -F',' '{print $4}'`
    local node2_ip_int=`grep "$node2_id" "$BUGALIZER_PRODUCTION_CSS" | awk -F',' '{print $5}'`
    local node1_name=`grep "$node1_id"   "$BUGALIZER_PRODUCTION_CSS" | awk -F',' '{print $3}'`
    local node2_name=`grep "$node2_id"   "$BUGALIZER_PRODUCTION_CSS" | awk -F',' '{print $3}'`
    node1_name="$node1_name   [$node1_id]"
    node2_name="$node2_name   [$node2_id]"
    #local node1_name=$(get_node_name "$folder1")
    #local node2_name=$(get_node_name "$folder2")

    # execute sip_viewer tool
    local sipv1="No SIP communication"
    local sipv2="No SIP communication"
    local sipv3="No SIP communication"
    if [[ ${inbound:0:4} == "SIP_" ]]; then
        echo -n "Executing sip_viewer for $ib... "
        sipv1=$(run_sip_view $trace1 $sip)
        echo "done"
    fi
    if [[ ${inbound2:0:4} == "SIP_" ]]; then
        echo -n "Executing sip_viewer for $ib2... "
        sipv2=$(run_sip_view $trace2 $sip_next)
        echo "done"
    fi
    
    draw_html "$caller" "$callee2" "$inbound" "$outbound" "$inbound2" "$outbound2" "$node1_name" "$node2_name" "$sip" "$sip_next" "$sip_next2" "$node1_ip_ext" "$node1_ip_int" "$node2_ip_ext" "$node2_ip_int" "$caller_ip" "$callee_ip" "$caller_name" "$callee_name" "$caller_client" "$callee_client" "$node1_version" "$node2_version"


    if ! [[ -z $stats1 ]] && ! [[ -z $stats2 ]]; then
        # ---> BW
        draw_html_stats_four "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_AUDIO_RX" "$STATS_AUDIO_TX" "$STATS_BW" "AUDIO_BW_LTR" "\&#8594 Audio BW" "$stats2" "$inbound2" "$outbound2" "$STATS_AUDIO_RX" "$STATS_AUDIO_TX"
        draw_html_stats_four "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_VIDEO_RX" "$STATS_VIDEO_TX" "$STATS_BW" "VIDEO_BW_LTR" "\&#8594 Video BW" "$stats2" "$inbound2" "$outbound2" "$STATS_VIDEO_RX" "$STATS_VIDEO_TX"
        draw_html_stats_four "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_PRESE_RX" "$STATS_PRESE_TX" "$STATS_BW" "PRESE_BW_LTR" "\&#8594 Presentation BW" "$stats2" "$inbound2" "$outbound2" "$STATS_PRESE_RX" "$STATS_PRESE_TX"

        # ---> Packets
        draw_html_stats_four "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_AUDIO_RX" "$STATS_AUDIO_TX" "$STATS_PACKETS" "AUDIO_PACKETS_LTR" "\&#8594 Audio Packets" "$stats2" "$inbound2" "$outbound2" "$STATS_AUDIO_RX" "$STATS_AUDIO_TX"
        draw_html_stats_four "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_VIDEO_RX" "$STATS_VIDEO_TX" "$STATS_PACKETS" "VIDEO_PACKETS_LTR" "\&#8594 Video Packets" "$stats2" "$inbound2" "$outbound2" "$STATS_VIDEO_RX" "$STATS_VIDEO_TX"
        draw_html_stats_four "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_PRESE_RX" "$STATS_PRESE_TX" "$STATS_PACKETS" "PRESE_PACKETS_LTR" "\&#8594 Presentation Packets" "$stats2" "$inbound2" "$outbound2" "$STATS_PRESE_RX" "$STATS_PRESE_TX"

        # ---> Packets loss
        draw_html_stats_four "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_AUDIO_RX" "$STATS_AUDIO_TX" "$STATS_LOSS" "AUDIO_LOSS_LTR" "\&#8594 Audio Loss" "$stats2" "$inbound2" "$outbound2" "$STATS_AUDIO_RX" "$STATS_AUDIO_TX"
        draw_html_stats_four "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_VIDEO_RX" "$STATS_VIDEO_TX" "$STATS_LOSS" "VIDEO_LOSS_LTR" "\&#8594 Video Loss" "$stats2" "$inbound2" "$outbound2" "$STATS_VIDEO_RX" "$STATS_VIDEO_TX"
        draw_html_stats_four "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_PRESE_RX" "$STATS_PRESE_TX" "$STATS_LOSS" "PRESE_LOSS_LTR" "\&#8594 Presentation Loss" "$stats2" "$inbound2" "$outbound2" "$STATS_PRESE_RX" "$STATS_PRESE_TX"


        # <--- BW
        draw_html_stats_four "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_AUDIO_TX" "$STATS_AUDIO_RX" "$STATS_BW" "AUDIO_BW_RTL" "\&#8592 Audio BW" "$stats2" "$inbound2" "$outbound2" "$STATS_AUDIO_TX" "$STATS_AUDIO_RX"
        draw_html_stats_four "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_VIDEO_TX" "$STATS_VIDEO_RX" "$STATS_BW" "VIDEO_BW_RTL" "\&#8592 Video BW" "$stats2" "$inbound2" "$outbound2" "$STATS_VIDEO_TX" "$STATS_VIDEO_RX"
        draw_html_stats_four "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_PRESE_TX" "$STATS_PRESE_RX" "$STATS_BW" "PRESE_BW_RTL" "\&#8592 Presentation BW" "$stats2" "$inbound2" "$outbound2" "$STATS_PRESE_TX" "$STATS_PRESE_RX"

        # <--- Packets
        draw_html_stats_four "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_AUDIO_TX" "$STATS_AUDIO_RX" "$STATS_PACKETS" "AUDIO_PACKETS_RTL" "\&#8592 Audio Packets" "$stats2" "$inbound2" "$outbound2" "$STATS_AUDIO_TX" "$STATS_AUDIO_RX"
        draw_html_stats_four "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_VIDEO_TX" "$STATS_VIDEO_RX" "$STATS_PACKETS" "VIDEO_PACKETS_RTL" "\&#8592 Video Packets" "$stats2" "$inbound2" "$outbound2" "$STATS_VIDEO_TX" "$STATS_VIDEO_RX"
        draw_html_stats_four "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_PRESE_TX" "$STATS_PRESE_RX" "$STATS_PACKETS" "PRESE_PACKETS_RTL" "\&#8592 Presentation Packets" "$stats2" "$inbound2" "$outbound2" "$STATS_PRESE_TX" "$STATS_PRESE_RX"

        # <--- Packets loss
        draw_html_stats_four "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_AUDIO_TX" "$STATS_AUDIO_RX" "$STATS_LOSS" "AUDIO_LOSS_RTL" "\&#8592 Audio Loss" "$stats2" "$inbound2" "$outbound2" "$STATS_AUDIO_TX" "$STATS_AUDIO_RX"
        draw_html_stats_four "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_VIDEO_TX" "$STATS_VIDEO_RX" "$STATS_LOSS" "VIDEO_LOSS_RTL" "\&#8592 Video Loss" "$stats2" "$inbound2" "$outbound2" "$STATS_VIDEO_TX" "$STATS_VIDEO_RX"
        draw_html_stats_four "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_PRESE_TX" "$STATS_PRESE_RX" "$STATS_LOSS" "PRESE_LOSS_RTL" "\&#8592 Presentation Loss" "$stats2" "$inbound2" "$outbound2" "$STATS_PRESE_TX" "$STATS_PRESE_RX"


        # --->
    #    draw_html_stats_two "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_AUDIO_RX" "$STATS_AUDIO_TX" "$STATS_BW" "AUDIO_BW" "---> Audio BW"
    #    draw_html_stats_two "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_VIDEO_RX" "$STATS_VIDEO_TX" "$STATS_BW" "VIDEO_BW" "---> Video BW"
    #    draw_html_stats_two "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_PRESE_RX" "$STATS_PRESE_TX" "$STATS_BW" "PRESE_BW" "---> Presentation BW"

        # <---
    #    draw_html_stats_two "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_AUDIO_RX" "$STATS_AUDIO_TX" "$STATS_BW" "AUDIO_BW" "<--- Audio BW"
    #    draw_html_stats_two "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_VIDEO_RX" "$STATS_VIDEO_TX" "$STATS_BW" "VIDEO_BW" "<--- Video BW"
    #    draw_html_stats_two "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_PRESE_RX" "$STATS_PRESE_TX" "$STATS_BW" "PRESE_BW" "<--- Presentation BW"

    #    draw_html_stats "$stats1" "$inbound" "$inbound" 3 1  "AUDIO1_TX_BW_DATA" "AUDIO1_TX_BW_MIN" "AUDIO1_TX_BW_MAX" "AUDIO1_TX_BW_JUMP" "AUDIO1_TX_BW_TITLE" "Audio TX BW"
    #    draw_html_stats "$stats1" "$inbound" "$inbound" 6 1  "VIDEO1_TX_BW_DATA" "VIDEO1_TX_BW_MIN" "VIDEO1_TX_BW_MAX" "VIDEO1_TX_BW_JUMP" "VIDEO1_TX_BW_TITLE" "Video TX BW"
    #    draw_html_stats "$stats1" "$inbound" "$inbound" 9 1  "PRES1_TX_BW_DATA"  "PRES1_TX_BW_MIN"  "PRES1_TX_BW_MAX"  "PRES1_TX_BW_JUMP"  "PRES1_TX_BW_TITLE"  "Presentation TX BW"
    #    draw_html_stats "$stats1" "$inbound" "$inbound" 4 1  "AUDIO1_RX_BW_DATA" "AUDIO1_RX_BW_MIN" "AUDIO1_RX_BW_MAX" "AUDIO1_RX_BW_JUMP" "AUDIO1_RX_BW_TITLE" "Audio RX BW"
    #    draw_html_stats "$stats1" "$inbound" "$inbound" 7 1  "VIDEO1_RX_BW_DATA" "VIDEO1_RX_BW_MIN" "VIDEO1_RX_BW_MAX" "VIDEO1_RX_BW_JUMP" "VIDEO1_RX_BW_TITLE" "Video RX BW"
    #    draw_html_stats "$stats1" "$inbound" "$inbound" 10 1 "PRES1_RX_BW_DATA"  "PRES1_RX_BW_MIN"  "PRES1_RX_BW_MAX"  "PRES1_RX_BW_JUMP"  "PRES1_RX_BW_TITLE"  "Presentation RX BW"

    #    draw_html_stats "$stats1" "$inbound" "$outbound" 3 1  "AUDIO2_TX_BW_DATA" "AUDIO2_TX_BW_MIN" "AUDIO2_TX_BW_MAX" "AUDIO2_TX_BW_JUMP" "AUDIO2_TX_BW_TITLE" "Audio TX BW"
    #    draw_html_stats "$stats1" "$inbound" "$outbound" 6 1  "VIDEO2_TX_BW_DATA" "VIDEO2_TX_BW_MIN" "VIDEO2_TX_BW_MAX" "VIDEO2_TX_BW_JUMP" "VIDEO2_TX_BW_TITLE" "Video TX BW"
    #    draw_html_stats "$stats1" "$inbound" "$outbound" 9 1  "PRES2_TX_BW_DATA"  "PRES2_TX_BW_MIN"  "PRES2_TX_BW_MAX"  "PRES2_TX_BW_JUMP"  "PRES2_TX_BW_TITLE"  "Presentation TX BW"
    #    draw_html_stats "$stats1" "$inbound" "$outbound" 4 1  "AUDIO2_RX_BW_DATA" "AUDIO2_RX_BW_MIN" "AUDIO2_RX_BW_MAX" "AUDIO2_RX_BW_JUMP" "AUDIO2_RX_BW_TITLE" "Audio RX BW"
    #    draw_html_stats "$stats1" "$inbound" "$outbound" 7 1  "VIDEO2_RX_BW_DATA" "VIDEO2_RX_BW_MIN" "VIDEO2_RX_BW_MAX" "VIDEO2_RX_BW_JUMP" "VIDEO2_RX_BW_TITLE" "Video RX BW"
    #    draw_html_stats "$stats1" "$inbound" "$outbound" 10 1 "PRES2_RX_BW_DATA"  "PRES2_RX_BW_MIN"  "PRES2_RX_BW_MAX"  "PRES2_RX_BW_JUMP"  "PRES2_RX_BW_TITLE"  "Presentation RX BW"

    fi


    replace_string_with_file_content "$inbound" "$sipv1" "SIP_VIEW_1"
    replace_string_with_file_content "$inbound" "$sipv2" "SIP_VIEW_2"
    replace_string_with_file_content "$inbound" "$sipv3" "SIP_VIEW_3"
    
    html_display "$inbound"
    echo ""
}

get_all ()
{
    local folder1=$1 # folder of node 1
    local folder2=$2 # folder of node 1
    local time=$3
    local caller=$4
    local ib=$5

    # check all necessary logs exist
    local trace1=`ls $folder1/*Trace*$time.log 2> /dev/null`
    local trace2=`ls $folder2/*Trace*$time.log 2> /dev/null`
    local stats1=`ls $folder1/*Stats*$time.log 2> /dev/null`
    local stats2=`ls $folder2/*Stats*$time.log 2> /dev/null`
    #local trans1=`ls $folder1/*Trans*$time.log`
    #local trans2=`ls $folder2/*Trans*$time.log`
    [[ ! -f $trace1 ]] && error_exit "Cannot find CallTrace log in $folder1"
    [[ ! -f $trace2 ]] && error_exit "Cannot find CallTrace log in $folder2"
    [[ ! -f $stats1 ]] && warn "Cannot find CallStats log in $folder1"
    [[ ! -f $stats2 ]] && warn "Cannot find CallStats log in $folder2"
    #[[ ! -f $trans1 ]] && error_exit "Cannot find Transactions log in $folder1"
    #[[ ! -f $trans2 ]] && error_exit "Cannot find Transactions log in $folder2"

    if [[ -z $ib ]]; then
        echo "Searching for inbound calls from $caller to $folder1"
        local call_handlers=$(get_all_call_handlers_ids_of_caller $trace1 $caller)
        local call_handlers_time=$(get_all_call_handlers_ids_of_caller $trace1 $caller "with_time")
        local call_handlers_num=`echo "$call_handlers" | wc -l`
        echo "Found $call_handlers_num inbound calls on $folder1:"
        for call in $call_handlers_time; do
            echo "  $call" | tr '-' ' '
        done

        # Read user input
        echo && echo -n "Enter inbound call ID (leave blank to analyse all): "
        read user_inbound
        echo
        
        if [[ -z $user_inbound ]]; then
            for inbound in $call_handlers; do
                get_one $inbound $folder1 $folder2 $time $caller $trace1 $trace2 $stats1 $stats2
            done
        else
            get_one "$user_inbound" "$folder1" "$folder2" "$time" "$caller" "$trace1" "$trace2" "$stats1" "$stats2"
        fi
    else
        local inbound=`grep _$ib $trace1 | grep INBOUND | head -1 | awk -F'|' '{print $7}'`
        #echo inbound is "$inbound"
        get_one "$inbound" "$folder1" "$folder2" "$time" "$caller" "$trace1" "$trace2" "$stats1" "$stats2"
    fi
}

run_sip_view ()
{
    local trace_file=$1
    local sip_id=$2

    trace=${trace_file:0:-4}   # remove extension
    local siptrace_file=$trace.siptrace.log
    local output_file=$trace.output.log
    local output_no_sip_file=$trace.output_no_msg.log

    if [[ ! -f $output_file ]]; then
        $BUGALIZER_SIPV "$trace_file"
    fi
    local lines_num=`grep $sip_id $output_file | wc -l`
    let lines_num=$lines_num+1
    grep "${sip_id::-1}" $output_no_sip_file -B3 -A$lines_num
}

draw_text_general ()
{
    local caller_ip=$1
    local callee_ip=$2
    local caller_name=$3
    local callee_name=$4
    local caller_client=$5
    local callee_client=$6

    echo "General:"
    echo "  Caller IP:     $caller_ip"
    echo "         Name:   $caller_name"
    echo "         Client: $caller_client"
    
    echo "  Callee IP:     $callee_ip"
    echo "         Name:   $callee_name"
    echo "         Client: $callee_client"
}

draw_text_node ()
{
    local node=$1
    local inbound=$2
    local outbound=$3
    local caller=$4
    local callee=$5
    local sip=$6
    local sip_next=$7
    local node_version=$8

    echo "Node: $node"
    echo "  Version:      $node_version"
    echo "  IB:           $inbound"
    echo "  OB:           $outbound"
    echo "  caller ext:   $caller"
    echo "  callee ext:   $callee"
    echo "  call-ID:      $sip"
    echo "  Next call-ID: $sip_next"
}

replace_string_with_file_content ()
{
    local inbound=$1
    local file_content=$2
    local str=$3

    local out="index${inbound: -5}.html"

    cp $out temp_$out
    awk -v r="$file_content" -v s="$str" '{gsub(s,r)}1' temp_$out > $out
    rm temp_$out
}

fix_slash ()
{
    echo "$1" | sed 's/\//\\\//g'
}

draw_html_stats_four ()
{
#   draw_html_stats_four "$stats1" "$inbound" "$inbound" "$outbound" "$STATS_AUDIO_RX" "$STATS_AUDIO_TX" "$STATS_BW" "AUDIO_BW" "---> Audio BW" "$stats2" "$inbound2" "$outbound2" "$STATS_AUDIO_RX" "$STATS_AUDIO_TX"

    local stats_file1=$1
    local inbound1=$2        # just for the file
    local call_handler_id_ib1=$3
    local call_handler_id_ob1=$4
    local index_medium1=$5
    local index_medium2=$6
    local index_bw_packets_loss1=$7
    local str=$8
    local title=$9
    local stats_file2=${10}
    local call_handler_id_ib2=${11}
    local call_handler_id_ob2=${12}
    local index_medium3=${13}
    local index_medium4=${14}
    #local index_bw_packets_loss2=${15}


    local str_data_rx1="$str"_DATA_RX1
    local str_data_tx1="$str"_DATA_TX1
    local str_data_rx2="$str"_DATA_RX2
    local str_data_tx2="$str"_DATA_TX2
    local str_data_lines_num="$str"_LINES_NUM
    local str_min="$str"_MIN
    local str_max="$str"_MAX
    local str_jump="$str"_JUMP
    local str_title="$str"_TITLE

    #echo $str_data_rx1
    #echo $str_data_tx1
    #echo $str_data_rx2
    #echo $str_data_tx2
    #echo $str_min
    #echo $str_max
    #echo $str_jump

    local out="index${inbound: -5}.html"

    debug ""
    debug "================================"
    debug "$title"
    debug "================================"

    # extract the data points
    local data_ib_rx1=`grep $call_handler_id_ib1 $stats_file1 | awk -F'|' -v col="$index_medium1" '{print $col}' | awk -F',' -v col="$index_bw_packets_loss1" '{print $col}'`
    local data_ob_tx1=`grep $call_handler_id_ob1 $stats_file1 | awk -F'|' -v col="$index_medium2" '{print $col}' | awk -F',' -v col="$index_bw_packets_loss1" '{print $col}'`
    local data_ib_rx2=`grep $call_handler_id_ib2 $stats_file2 | awk -F'|' -v col="$index_medium3" '{print $col}' | awk -F',' -v col="$index_bw_packets_loss1" '{print $col}'`
    if ! [[ -z $call_handler_id_ob2 ]]; then    # sometimes second OB leg doesn't exist
        local data_ob_tx2=`grep $call_handler_id_ob2 $stats_file2 | awk -F'|' -v col="$index_medium4" '{print $col}' | awk -F',' -v col="$index_bw_packets_loss1" '{print $col}'`
    fi

    # remove first 0
    [[ ${data_ib_rx1:0:1} == 0 ]] && data_ib_rx1=${data_ib_rx1:2}
    [[ ${data_ob_tx1:0:1} == 0 ]] && data_ob_tx1=${data_ob_tx1:2}
    [[ ${data_ib_rx2:0:1} == 0 ]] && data_ib_rx2=${data_ib_rx2:2}
    [[ ${data_ob_tx2:0:1} == 0 ]] && data_ob_tx2=${data_ob_tx2:2}
    
    local data_ib_rx1_num=`echo "$data_ib_rx1" | wc -l`
    local data_ob_tx1_num=`echo "$data_ob_tx1" | wc -l`
    local data_ib_rx2_num=`echo "$data_ib_rx2" | wc -l`
    local data_ob_tx2_num=`echo "$data_ob_tx2" | wc -l`
    local data_lines_all=`echo "$data_ib_rx1_num"; echo "$data_ob_tx1_num"; echo "$data_ib_rx2_num"; echo "$data_ob_tx2_num"`
    local data_points_num=`echo "$data_lines_all" | sort -n | tail -1`
    debug "data_ib_rx1_num: $data_ib_rx1_num"
    debug "data_ob_tx1_num: $data_ob_tx1_num"
    debug "data_ib_rx2_num: $data_ib_rx2_num"
    debug "data_ob_tx2_num: $data_ob_tx2_num"
    debug "data_points_num: $data_points_num"

    # find min, max, and jump
    local data_all=`echo "$data_ib_rx1"; echo "$data_ob_tx1"; echo "$data_ib_rx2"; echo "$data_ob_tx2"`
    local min=`echo "$data_all" | sort -n | head -1`
    local max=`echo "$data_all" | sort -n | tail -1`
    let jump=$max-$min
    #let jump=$jump/2

    data_ib_rx1=`echo $data_ib_rx1 | tr ' ' ','`
    data_ob_tx1=`echo $data_ob_tx1 | tr ' ' ','`
    data_ib_rx2=`echo $data_ib_rx2 | tr ' ' ','`
    data_ob_tx2=`echo $data_ob_tx2 | tr ' ' ','`
    debug "data_ib_rx1: $data_ib_rx1"
    debug "data_ob_tx1: $data_ob_tx1"
    debug "data_ib_rx2: $data_ib_rx2"
    debug "data_ob_tx2: $data_ob_tx2"
    debug "min:  $min"
    debug "max:  $max"
    debug "jump: $jump"

    sed -i -e "s/$str_data_rx1/$data_ib_rx1/g" $out
    sed -i -e "s/$str_data_tx1/$data_ob_tx1/g" $out
    sed -i -e "s/$str_data_rx2/$data_ib_rx2/g" $out
    sed -i -e "s/$str_data_tx2/$data_ob_tx2/g" $out
    sed -i -e "s/$str_data_lines_num/$data_points_num/g" $out
    sed -i -e "s/$str_min/$min/g" $out
    sed -i -e "s/$str_max/$max/g" $out
    sed -i -e "s/$str_jump/$jump/g" $out
    sed -i -e "s/$str_title/$title/g" $out
}

draw_html_stats_two ()
{
#   draw_html_stats_two "$stats1" "$inbound" "$inbound" "$outbound" 4 3 "AUDIO_BW" "Audio BW"
    local stats_file=$1
    local inbound=$2        # just for the file
    local call_handler_id_ib=$3
    local call_handler_id_ob=$4
    local index_audio_video_pres1=$5
    local index_audio_video_pres2=$6
    local index_bw_packets_loss=$7
    local str=$8
    local title=$9

    local str_data_rx="$str"_DATA_RX
    local str_data_tx="$str"_DATA_TX
    local str_min="$str"_MIN
    local str_max="$str"_MAX
    local str_jump="$str"_JUMP
    local str_title="$str"_TITLE

    debug $str_data_rx
    debug $str_data_tx
    debug $str_min
    debug $str_max
    debug $str_jump

    local out="index${inbound: -5}.html"

    local data_ib_rx=`grep $call_handler_id_ib $stats_file | awk -F'|' -v col="$index_audio_video_pres1" '{print $col}' | awk -F',' -v col="$index_bw_packets_loss" '{print $col}'`
    local data_ob_tx=`grep $call_handler_id_ob $stats_file | awk -F'|' -v col="$index_audio_video_pres2" '{print $col}' | awk -F',' -v col="$index_bw_packets_loss" '{print $col}'`
    local data_all=`echo "$data_ib_rx"; echo "$data_ob_tx"`
    local min=`echo "$data_all" | sort -n | head -1`
    local max=`echo "$data_all" | sort -n | tail -1`
    let jump=$max-$min
    #let jump=$jump/2
    data_ib_rx=`echo $data_ib_rx | tr ' ' ','`
    data_ob_tx=`echo $data_ob_tx | tr ' ' ','`
    debug "data_ib_rx: $data_ib_rx"
    debug "data_ob_tx: $data_ob_tx"
    debug "min:  $min"
    debug "max:  $max"
    debug "jump: $jump"

    sed -i -e "s/$str_data_rx/$data_ib_rx/g" $out
    sed -i -e "s/$str_data_tx/$data_ob_tx/g" $out
    sed -i -e "s/$str_min/$min/g" $out
    sed -i -e "s/$str_max/$max/g" $out
    sed -i -e "s/$str_jump/$jump/g" $out
    sed -i -e "s/$str_title/$title/g" $out
}

draw_html_stats ()
{
    local trace_file=$1
    local inbound=$2        # just for the file
    local call_handler_id=$3
    local index_audio_video_pres=$4
    local index_bw_packets_loss=$5
    local str_data=$6
    local str_min=$7
    local str_max=$8
    local str_jump=$9
    local str_title=${10}
    local title=${11}

    local out="index${inbound: -5}.html"

    local data=`grep $call_handler_id $trace_file | awk -F'|' -v var1="$index_audio_video_pres" '{print $var1}' | awk -F',' -v var2="$index_bw_packets_loss" '{print $var2}'`
    local min=`echo "$data" | sort -n | head -1`
    local max=`echo "$data" | sort -n | tail -1`
    let jump=$max-$min
    let jump=$jump/2
    data=`echo $data | tr ' ' ','`
    debug "data: $data"
    debug "min:  $min"
    debug "max:  $max"
    debug "jump: $jump"

    sed -i -e "s/$str_data/$data/g" $out
    sed -i -e "s/$str_min/$min/g" $out
    sed -i -e "s/$str_max/$max/g" $out
    sed -i -e "s/$str_jump/$jump/g" $out
    sed -i -e "s/$str_title/$title/g" $out
}

is_caller_voxbone () { [[ $(expr "$1" : '.*voxbone\.com') != 0 ]]; }
is_caller_twilio ()  { [[ $(expr "$1" : '.*twilio\.com') != 0 ]]; }

draw_html ()
{
    local caller=$1
    local callee=$2
    local inbound=$3
    local outbound=$4
    local inbound2=$5
    local outbound2=$6
    local folder1=$7
    local folder2=$8
    local sip=$9
    local sip_next=${10}
    local sip_next2=${11}
    local node1_ip_ext=${12}
    local node1_ip_int=${13}
    local node2_ip_ext=${14}
    local node2_ip_int=${15}
    local caller_ip=${16}
    local callee_ip=${17}
    local caller_name=${18}
    local callee_name=${19}
    local caller_client=${20}
    local callee_client=${21}
    local node1_version=${22}
    local node2_version=${23}

    local out="index${inbound: -5}.html"

    echo Creating $out
    cp $SCRIPTPATH/index.html.orig $out
    
    local css_style=`cat $SCRIPTPATH/bugalyzer.css`
    replace_string_with_file_content $inbound "$css_style" "STYLE_FROM_CSS_FILE"

    if $(is_caller_voxbone $caller_name); then
        caller_name=`expr "$caller_name" : '\(.*voxbone\.com\)'`
    elif $(is_caller_twilio $caller_name); then
        caller_name=`expr "$caller_name" : '\(.*twilio\.com\)'`
    fi

    sed -i -e "s/CALLER_EXTENSION/$caller/g" $out
    sed -i -e "s/CALLEE_EXTENSION/$callee/g" $out
    sed -i -e "s/CALLER_NAME/$caller_name/g" $out
    sed -i -e "s/CALLEE_NAME/$callee_name/g" $out
    caller_client=${caller_client:0:-1}
    caller_client=$(fix_slash "$caller_client")
    sed -i -e "s/CALLER_CLIENT/$caller_client/g" "$out"
    sed -i -e "s/CALLEE_CLIENT/$callee_client/g" $out

    sed -i -e "s/NODE1_VERSION/$node1_version/g" $out
    sed -i -e "s/NODE2_VERSION/$node2_version/g" $out
    sed -i -e "s/NODE1_IB_4DIGITS/${inbound: -4}/g" $out
    sed -i -e "s/NODE1_OB_4DIGITS/${outbound: -4}/g" $out
    sed -i -e "s/NODE2_IB_4DIGITS/${inbound2: -4}/g" $out
    sed -i -e "s/NODE2_OB_4DIGITS/${outbound2: -4}/g" $out
    sed -i -e "s/NODE1_IB_TOOLTIP/$inbound/g" $out
    sed -i -e "s/NODE1_OB_TOOLTIP/$outbound/g" $out
    sed -i -e "s/NODE2_IB_TOOLTIP/$inbound2}/g" $out
    sed -i -e "s/NODE2_OB_TOOLTIP/$outbound2/g" $out
    sed -i -e "s/NODE1_NAME/$folder1/g" $out
    sed -i -e "s/NODE2_NAME/$folder2/g" $out
    sed -i -e "s/CALL_ID_1_12DIGITS/${sip:0:12}/g" $out
    sed -i -e "s/CALL_ID_2_12DIGITS/${sip_next:0:12}/g" $out
    sed -i -e "s/CALL_ID_3_12DIGITS/${sip_next2:0:12}/g" $out
    sed -i -e "s/CALL_ID_1_TOOLTIP/$sip/g" $out
    sed -i -e "s/CALL_ID_2_TOOLTIP/$sip_next/g" $out
    sed -i -e "s/CALL_ID_3_TOOLTIP/$sip_next2/g" $out
    sed -i -e "s/NODE1_IP_EXT/$node1_ip_ext/g" $out
    sed -i -e "s/NODE1_IP_INT/$node1_ip_int/g" $out
    sed -i -e "s/NODE2_IP_EXT/$node2_ip_ext/g" $out
    sed -i -e "s/NODE2_IP_INT/$node2_ip_int/g" $out
    sed -i -e "s/CALLER_IP/$caller_ip/g" $out
    sed -i -e "s/CALLEE_IP/$callee_ip/g" $out
    #[[ ! -z $sip_next2 ]] && sed -i -e "s/CALL_ID_3/$sip_next2/g" $out
}

html_display ()
{
    local inbound=$1

    local out="index${inbound: -5}.html"
    firefox $out &
}

clean_exit ()
{
    rm "$TRACE_GREPPED"*
}

check_dependencies ()
{
    dpkg -s jq > /dev/null 2>&1 || error_exit "jq package is missing. Please install it first (Linux: \"sudo apt-get install jq\")"
}

check_dependencies
load_config

subcommand=$1
case $subcommand in
    "" | "-h" | "--help")           sub_help ;;
    -o|--outbound-by-inbound)       shift && get_outbound_by_inbound $@    ; shift ;;
    -r|--caller-by-inbound)         shift && get_caller_by_inbound $@      ; shift ;;
    -t|--caller-name-by-inbound)    shift && get_caller_name_by_inbound $@ ; shift ;;
    -e|--callee-by-inbound)         shift && get_callee_by_inbound $@      ; shift ;;
    -i|--inbound-by-outbound)       shift && get_inbound_by_outbound $@    ; shift ;;
    -s|--sip-by-inbound)            shift && get_sip_id_by_inbound $@      ; shift ;;
    -n|--next-sip-by-inbound)       shift && get_next_sip_id_by_inbound $@ ; shift ;;
    -x|--inbound-by-sip)            shift && get_inbound_by_sip_id $@      ; shift ;;
    -y|--outbound-by-sip)           shift && get_outbound_by_sip_id $@     ; shift ;;
    -z|--nextsip-by-sip)            shift && get_next_sip_id_by_sip_id $@  ; shift ;;
    -m|--mp-by-outbound)            shift && get_mp_by_outbound $@         ; shift ;;
    -a|--all-call-handlers-ids)     shift && get_all_call_handlers_ids $@  ; shift ;;
    -b|--all-call-handlers-ids-of-caller) shift && get_all_call_handlers_ids_of_caller $@  ; shift ;;
    -q|--all)                   shift && get_all $@                    ; shift ;;
    *) get_${subcommand} $@
       if [ $? = 127 ]; then
           echo "Error: '$subcommand' is not a known subcommand." >&2
           echo "       Run '$ProgName --help' for a list of known subcommands." >&2
           exit 1
       fi
       ;;
esac

clean_exit

