# @TEST-EXEC: zeek -C -r $TRACES/cups-evilprinter.pcap  ../../../scripts %INPUT
# @TEST-EXEC: btest-diff notice.log

