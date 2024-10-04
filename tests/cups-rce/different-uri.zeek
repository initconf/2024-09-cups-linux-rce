# @TEST-EXEC: zeek -C -r $TRACES/different-uri.pcap  ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

