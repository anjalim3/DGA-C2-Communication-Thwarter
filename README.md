# DGA-C2 Communication Thwarter
Tool to thwart DGA component of malicious process from successfully connecting to C2 by blocking DNS responses

## Run

1. Route incoming DNS responses to our software:

    ```angular2html
    sudo iptables -I INPUT -p udp --sport 53 -j NFQUEUE --queue-num 1
    ```

2. Start our software:
    ```angular2html
    sudo python netfilterqueue_preroute.py
    ```

3. Mark pids that are dead:
    ```
    python kill_dead_pids.py
    ```
