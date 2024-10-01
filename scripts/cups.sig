signature cups-rce-attempt  {
    ip-proto == udp
    dst-port == 631
    payload  /.*((https?|ftp|ipp):\/\/[-a-zA-Z0-9+&@#\/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#\/%=~_|])/
    #payload /.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/
    event "LINUX CUPS RCE!!!"
}

