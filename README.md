# 42_ft_nmap

#### Overview
Implementation of our own port-scanner based on nmap's scans (SYN, ACK, FIN, XMAS, NUL and UDP).

#### Options
-    -h, --help
-    -p, --port=NB[-NB]
-    -s, --scan=S|A|U|F|N|X
-    -t, --threads=NB
-    -n, --no-dns 
-    -r, --reason 
-    -m, --max-retries=NB
-    -f, --file=FILE 
-    -d, --scan-delay=NB

#### Information
- requires superuser privileges
- functional on Debian GNU/Linux 12

#### Usage
    make && ./ft_nmap
    
#### Authors

- [@runeons](https://www.github.com/runeons)
- [@yorgs](https://www.github.com/yorgsone)
