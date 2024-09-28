# @TEST-EXEC: zeek -C -r $TRACES/udp.pcap  ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

