# Advanced Networks Topics

## 1. Analysis of packet trace
    # ---------------------------------------------------
    # TCP Header Size without Option - 20 bytes
    # TCP Options:
    # ---------------
    # Maximum Segment Size           mss       4 bytes
    # Window Scaling                 wscale    3 bytes
    # Selective Acknowledgements
    #   SACK-Permitted Option        sackOK    2 bytes
    #   SACK Option                       (4n+2) bytes (n is no. of block)
    #       e.g. "sack sack 1 {0:536}" -- 1 block
    # Timestamps                              10 bytes
    # No-Operation                   nop       1 byte
    # End of option list             eol       1 byte
    # Connection Count New           ccnew     6 byte
    # ---------------------------------------------------
    
    # ---------------
    # tcpdump Flags:
    # ---------------
    # TCP Flag	tcpdump Flag	Meaning
    #   SYN	        S	        Syn packet, a session establishment request.
    #   ACK	        A	        Ack packet, acknowledge sender’s data.
    #   FIN	        F	        Finish flag, indication of termination.
    #   RESET	    R	        Reset, indication of immediate abort of conn.
    #   PUSH	    P	        Push, immediate push of data from sender.
    #   URGENT	    U	        Urgent, takes precedence over other data.
    #   NONE	  A dot .	    Placeholder, usually used for ACK.
    #   ECE-Echo    E           ECN: Explicit Congestion Notification
    #   ECN CWR     W           CWR: Congestion Window Reduced
    # ------------------------------------------------------------------------------
    # Tcpflags are some combination of S (SYN), F (FIN), P (PUSH), R (RST), U (URG),
    # W (ECN CWR), E (ECN-Echo) or `.' (ACK), or `none' if no flags are set.
    # ------------------------------------------------------------------------------

## 2. Implement routing algorithm (Dijkstra)
Note: to find the minimum-hop path, set all weights to 1.
