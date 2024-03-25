if [ "$1" == "--compile" ]
then
    echo "Loading environment variables"
    source env.sh
    echo "Recompiling..."
    ninja -C build
elif [ "$1" == "--default" ]
then
    echo "Running program..."
    sudo bash -c 'source env.sh && ./build/gpu-hostnic -a 33:00.0 -a 36:00.0 -l 0-5 -- -o "test.pcap" -q 2'
else
    args="source env.sh && ./build/gpu-hostnic -a 33:00.0 -a 36:00.0 ${@:1}"
    sudo bash -c "$args"
fi