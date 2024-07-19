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

    #open
    "1.1.1.1, 53, S" # open (expected filtered)
    "8.8.8.8, 53, U"

    #closed
    "sapin.fr, 23, S"
    "sapin.fr, 161, U"
    # "localhost, 60011, U"
    # "127.0.0.1, 60011, U"
    # "127.0.0.1, 60011, S"
    # "freebsd.org, 44444, U"
    # "google.fr, 443, F"
    # "google.fr, 443, N"
    # "google.fr, 443, X"

    #open|filtered
    "127.0.0.1, 22, F"  #closed (expected open|filtered)
    # "127.0.0.1, 22, N"  #closed (expected open|filtered)
    # "127.0.0.1, 22, X"  #closed (expected open|filtered)

    #unfiltered
    "sapin.fr, 3389, A"

    #filtered
    "1.1.1.125, 53, S"

    #localhost exhaustive tests
    # "127.0.0.1, 5353, S"           # closed OK
    # "127.0.0.1, 5353, U"           # closed OK
    # "127.0.0.1, 5353, A"           #filtered (expected unfiltered)
    # "127.0.0.1, 5353, F"           #open|filtered (expected closed)
    # "127.0.0.1, 5353, N"
    # "127.0.0.1, 5353, X"
    # "127.0.0.1, 60012, S"           # closed OK
    # "127.0.0.1, 60012, U"           # closed OK
    # "127.0.0.1, 60012, A"           #filtered (expected unfiltered)
    # "127.0.0.1, 60012, F"           #open|filtered (expected closed)
    # "127.0.0.1, 60012, N"
    # "127.0.0.1, 60012, X"
    "127.0.0.1, 22, S"              #open # got closed
    "127.0.0.1, 22, U"              #closed
    "127.0.0.1, 22, A"              #unfiltered # got filtered
    "127.0.0.1, 22, F"              #open|filtered
    "127.0.0.1, 22, N"              #open|filtered
    "127.0.0.1, 22, X"              #open|filtered

)

for test in "${tests[@]}"; do
    IFS=',' read -r target port scan expected <<< "$test"
    run_test $target $port $scan
done