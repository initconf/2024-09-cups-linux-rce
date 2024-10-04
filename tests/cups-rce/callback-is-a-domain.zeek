# @TEST-EXEC: zeek -C -r $TRACES/callback-is-a-domain.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

