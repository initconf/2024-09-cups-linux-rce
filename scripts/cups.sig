signature cups-rce-attempt  {
    ip-proto == udp
    dst-port == 631
    payload /.*print/
    event "LINUX CUPS RCE!!!"
}

