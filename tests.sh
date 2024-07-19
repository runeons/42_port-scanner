GREEN='\033[0;32m'
RED='\033[0;31m'
RES='\033[0m'

run_test()
{
    local target=$1
    local port=$2
    local scan=$3
    local expected=$4

    local nmap_result=$(sudo nmap $target -p $port -s$scan)
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
    # echo "${nmap_result}"
    # echo "${ft_nmap_result}"
}

declare -a tests=(
    # "1.1.1.1, 53, S, open"
    # "sapin.fr, 23, S, closed"
    # "1.1.1.125, 53, S, filtered"

    # "8.8.8.8, 53, U, open"
    # "sapin.fr, 161, U, closed"
    "127.0.0.1, 60011, U, closed"         
    "127.0.0.1, 60011, S, closed"         
    # "freebsd.org, 44444, U, closed"

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