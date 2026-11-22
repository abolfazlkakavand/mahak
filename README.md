# Mahak

Adaptive DPI-evasion SOCKS5 engine and network probe for Termux/Android.

Mahak tries several ways of sending the TLS ClientHello (record splitting, TCP splitting, urgent byte, disorder, low-TTL decoys) and keeps the one that works on the current network, per host. The wire-level tricks come from the MIT-licensed [desync](https://github.com/Nemu-x/desync) library (itself following ByeDPI and zapret); strategy rotation, learning, DoH resolving and the probe are Mahak's own.

```
mahak probe            # test every strategy on this network, write mahak-report.json
mahak serve            # SOCKS5 on 127.0.0.1:10808
```

Status: v0.1, untested on a real filtered network.
