
### =======================================================================
## Simple policy to detect CUPS LINUX remote code execution vulnerability attempts and successes
### https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I/
### =======================================================================

## Following functionality are provided by the script
--------------------------------------------------
## Installation
------------
	zeek-pkg install zeek/initconf/cups_rce
	or
	@load cups_rce/scripts

## Detailed Notes:
---------------
Detail Alerts and descriptions: Following alerts are generated by the script:
******************************************************************************
Heuristics are simple: check for  (i) Signature match on callback URL  (ii) POST request on Callback URL
This should generate following Kinds of notices:

## Example notice:
```
[ Signature Match ]


1727428593.470887       CCaBx639KU9NNYfEg4      196.226.16.57   38552   129.61.5.5      631
 -       -       -       udp     Signatures::Sensitive_Signature 196.226.16.57: LINUX CUPS RCE!!!        0 3
http://194.164.193.43:1234/printers/NAME "Office HQ" "Printer"     196.226.16.57   129.61.5.5      631     -
Notice::ACTION_LOG      (empty) 3600.000000     -       -       -       -       -

```


```
[ CUPS Attempt ]

<sub>
1727428803.636599       -       -       -       -       -       -       -       -       -       CUPS::Attempt   CUPS :
196.226.16.57 - Sources : [LINUX CUPS RCE!!! [0 3 http://194.164.193.43:1234/printers/NAME "Office HQ" "Printer"]]      -
196.226.16.57   -       -       -       -       Notice::ACTION_LOG,Notice::ACTION_DROP  (empty) 1800.000000
```

## Example Summary Notice:
***************************

Also this generates:

```
1) Notice::Signatures::Sensitive_Signature


Sep 27 12:27:22 CaGpESdoizvXAbp62       107.170.72.202  53319   128.3.0.127     631     -       -       -       udp
 Signatures::Sensitive_Signature 107.170.72.202: LINUX CUPS RCE!!!       00 03
http://192.34.63.88:5674/printers/securitytest3/\x00      107.170.72.202  128.3.0.127     631     -       -
Notice::ACTION_LOG      (empty) 3600.000000     -       -       -       -       -
```

```
2) Notice::Signatures::Multiple_Sig_Responders

Sep 27 12:27:22 -       -       -       -       -       -       -       -       -       Signatures::Multiple_Sig_Responders
LINUX CUPS RCE!!!       107.170.72.202 has triggered signature cups-rce-attempt on 5 hosts      107.170.72.202  -       -       5
     -       Notice::ACTION_LOG      (empty) 3600.000000     -       -       -       -       -

Sep 27 12:27:22 -       -       -       -       -       -       -       -       -       Signatures::Multiple_Sig_Responders
LINUX CUPS RCE!!!       107.170.72.202 has triggered signature cups-rce-attempt on 10 hosts     107.170.72.202  -       -       10
     -       Notice::ACTION_LOG      (empty) 3600.000000     -       -       -       -       -

Sep 27 12:27:22 -       -       -       -       -       -       -       -       -       Signatures::Multiple_Sig_Responders
LINUX CUPS RCE!!!       107.170.72.202 has triggered signature cups-rce-attempt on 50 hosts     107.170.72.202  -       -       50
     -       Notice::ACTION_LOG      (empty) 3600.000000     -       -       -       -       -

Sep 27 12:27:22 -       -       -       -       -       -       -       -       -       Signatures::Multiple_Sig_Responders
LINUX CUPS RCE!!!       107.170.72.202 has triggered signature cups-rce-attempt on 100 hosts    107.170.72.202  -       -
100     -       Notice::ACTION_LOG      (empty) 3600.000000     -       -       -       -       -

Sep 27 12:27:22 -       -       -       -       -       -       -       -       -       Signatures::Multiple_Sig_Responders
LINUX CUPS RCE!!!       107.170.72.202 has triggered signature cups-rce-attempt on 500 hosts    107.170.72.202  -       -
500     -       Notice::ACTION_LOG      (empty) 3600.000000     -       -       -       -       -

Sep 27 12:27:22 -       -       -       -       -       -       -       -       -       Signatures::Multiple_Sig_Responders
LINUX CUPS RCE!!!       107.170.72.202 has triggered signature cups-rce-attempt on 1000 hosts   107.170.72.202  -       -
1000    -       Notice::ACTION_LOG      (empty) 3600.000000     -       -       -       -       -
```

```
3) Notice::CUPS::Attempt

Sep 27 12:31:51 -       -       -       -       -       -       -       -       -       CUPS::Attempt   CUPS : 107.170.72.202 -
Sources : [LINUX CUPS RCE!!! [00 03 http://192.34.63.88:5674/printers/securitytest3/\x00]]      -       107.170.72.202  -       -
Notice::ACTION_DROP,Notice::ACTION_LOG  (empty) 1800.000000     -       -       -       -       -

Sep 27 13:28:11 -       -       -       -       -       -       -       -       -       CUPS::Attempt   CUPS : 107.170.72.202 -
Sources : [LINUX CUPS RCE!!! [0 3 http://192.34.63.88:5674/printers/securitytest3/\x00]]        -       107.170.72.202  -       -
      -       -       Notice::ACTION_DROP,Notice::ACTION_LOG  (empty) 1800.000000     -       -       -       -       -

Sep 27 14:26:42 -       -       -       -       -       -       -       -       -       CUPS::Attempt   CUPS : 107.170.72.202 -
Sources : [LINUX CUPS RCE!!! [00 03 http://192.34.63.88:5674/printers/securitytest3/\x00]]      -       107.170.72.202  -       -
      -       -       Notice::ACTION_DROP,Notice::ACTION_LOG  (empty) 1800.000000     -       -       -       -       -

Sep 27 15:33:49 -       -       -       -       -       -       -       -       -       CUPS::Attempt   CUPS : 107.170.72.202 -
Sources : [LINUX CUPS RCE!!! [0 3 http://192.34.63.88:5674/printers/securitytest3/\x00]]        -       107.170.72.202  -       -
      -       -       Notice::ACTION_DROP,Notice::ACTION_LOG  (empty) 1800.000000     -       -       -       -       -

```






