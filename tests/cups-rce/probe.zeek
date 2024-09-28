# @TEST-EXEC: zeek -C -r $TRACES/probe.pcap  ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

