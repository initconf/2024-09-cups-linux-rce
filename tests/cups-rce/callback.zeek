# @TEST-EXEC: zeek -C -r $TRACES/callback.pcap  ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

