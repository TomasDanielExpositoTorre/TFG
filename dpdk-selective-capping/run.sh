if [ "$1" == "--compile" ]
then
    echo "Loading environment variables"
    source env.sh
    echo "Recompiling..."
    ninja -C build
else
    args="source env.sh && ./build/dpdk-selective-capping -a 33:00.0 -a 36:00.0 -l 0-4 --file-prefix capture -- -o "test.pcap" -q 1 ${@:1}"
    sudo bash -c "$args"
fi