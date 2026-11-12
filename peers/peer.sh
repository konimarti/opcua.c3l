#!/bin/bash
# Starts or stops a test peer and writes peers/peer.env for it (the peer tests read that file).
#   peers/peer.sh start open62541|asyncua [port]     peers/peer.sh stop open62541|asyncua
# open62541: the prebuilt ci_server in .work/peer/open62541 (run only). asyncua: peers/asyncua_server.py in the venv
# of .work/peer/venv (run only). OPCUA_PEER_PID in peer.env lets the renewal test pause the peer (SIGSTOP / SIGCONT).
set -eu
cd "$(dirname "$0")/.."
action=$1
peer=$2
port=${3:-}
pidfile=peers/$peer.pid
case "$action:$peer" in
start:open62541)
	port=${port:-4840}
	nohup .work/peer/open62541/ci_server "$port" > peers/$peer.log 2>&1 &
	echo $! > "$pidfile"
	sleep 2
	cat > peers/peer.env <<ENV
OPCUA_PEER_URL=opc.tcp://127.0.0.1:$port
OPCUA_NODE_INT32=ns=1;s=the.answer
OPCUA_NODE_METHOD_OBJECT=ns=0;i=85
OPCUA_NODE_METHOD=ns=1;i=62541
OPCUA_METHOD_KIND=string
OPCUA_PEER_PID=$(cat "$pidfile")
ENV
	;;
start:asyncua)
	port=${port:-4841}
	nohup .work/peer/venv/bin/python peers/asyncua_server.py "$port" peers/peer.env > peers/$peer.log 2>&1 &
	echo $! > "$pidfile"
	sleep 4
	echo "OPCUA_PEER_PID=$(cat "$pidfile")" >> peers/peer.env
	;;
stop:*)
	if [ -f "$pidfile" ]; then
		pid=$(cat "$pidfile")
		# only signal the process we started: it must be alive and its command line must name our peer
		if kill -0 "$pid" 2>/dev/null && tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -qE 'ci_server|asyncua_server'; then
			kill -CONT "$pid" 2>/dev/null || true
			kill "$pid" 2>/dev/null || true
		fi
		rm -f "$pidfile"
	fi
	;;
*)
	echo "usage: $0 start|stop open62541|asyncua [port]" >&2
	exit 2
	;;
esac
