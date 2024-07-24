GREEN='\033[0;32m'
RED='\033[0;31m'
RES='\033[0m'

run_test()
{
    local target=$1
    local port=$2
    local scan=$3
    local expected=$4

    local nmap_result=$(sudo nmap $target -p $port -s$scan -Pn)
    local nmap_conclusion=$(echo "$nmap_result" | grep "^$port" | awk '{print $2}')
    local ft_nmap_result=$(sudo ./ft_nmap $target -p $port -s $scan)
    local ft_nmap_conclusion=$(echo "$ft_nmap_result" | grep "| *$port/" | awk '{print $(NF-1)}')
    echo "${target} -p ${port} -s ${scan}"
    if [ "$nmap_conclusion" == "$ft_nmap_conclusion" ]; then
        echo -e "          ${GREEN}OK${RES} $nmap_conclusion"
    else
        echo -e "          ${RED}KO${RES} $ft_nmap_conclusion (expected $nmap_conclusion)"
    fi
    echo
}

declare -a tests=(

    #open
    "1.1.1.1, 53, S"
    "1.1.1.1, 53, A"
    "8.8.8.8, 53, U"
    "0, 53, A"
    "0, 631, S"

    #closed
    "sapin.fr, 23, S"
    "sapin.fr, 161, U"
    "localhost, 60011, U"
    "127.0.0.1, 60011, U"
    "127.0.0.1, 60011, S"
    "freebsd.org, 44444, U"
    "google.fr, 443, F"
    "google.fr, 443, N"
    "google.fr, 443, X"

    #open|filtered
    "127.0.0.1, 22, F"
    "127.0.0.1, 22, N"
    "127.0.0.1, 22, X"

    #unfiltered
    "sapin.fr, 3389, A"

    #filtered
    "1.1.1.125, 53, S"

    #localhost exhaustive tests
    "127.0.0.1, 22, S"
    "localhost, 22, U"
    "127.0.0.1, 22, A"
)

for test in "${tests[@]}"; do
    IFS=',' read -r target port scan expected <<< "$test"
    run_test $target $port $scan
done