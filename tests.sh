GREEN='\033[0;32m'
RED='\033[0;31m'
RES='\033[0m'

run_test()
{
    local target=$1
    local port=$2
    local scan=$3
    local expected=$4

    echo -e "${GREEN}------------------------------------------------------------------------------------------${RES}"
    echo -e "${GREEN}nmap   : sudo nmap $target -p $port -s$scan${RES}"
    sudo nmap $target -p $port -s$scan
    echo -e "${GREEN}ft_nmap: sudo ./ft_nmap $target -p $port -s$scan${RES}"
    sudo ./ft_nmap $target -p $port -s $scan
    echo -e "${GREEN}Expected: $expected${RES}"
    echo -e "${GREEN}------------------------------------------------------------------------------------------${RES}"
    echo
}

declare -a tests=(
    # "1.1.1.1, 53, S, open"
    # "sapin.fr, 23, S, closed"
    # "1.1.1.125, 53, S, filtered" # long but OK

    # "8.8.8.8, 53, U, open"
    # "sapin.fr, 161, U, closed"          # ICMP_UNREACH_3 implemented
    "127.0.0.1, 60011, U, closed"       # long and wrong - should receive response
    "freebsd.org, 44444, U, filtered"   # long and wrong - should receive response

    # "127.0.0.1, 22, F, open|filtered"
    # "google.fr, 443, F, closed"

    # "sapin.fr, 3389, A, unfiltered"

    # "127.0.0.1, 22, N, open|filtered"
    # "google.fr, 443, N, closed"

    # "127.0.0.1, 22, X, open|filtered"
    # "google.fr, 443, X, closed"

)

for test in "${tests[@]}"; do
    IFS=',' read -r target port scan expected <<< "$test"
    run_test $target $port $scan $expected
done