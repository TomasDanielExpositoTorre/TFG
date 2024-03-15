if [ "$1" == "c" ]
then
    echo "Loading environment variables"
    source env.sh
    echo "Recompiling..."
    ninja -C build
else
    echo "Running program..."
    sudo bash -c 'source env.sh && ./build/gpu-hostnic -a 33:00.0 -a 36:00.0 -l 0-4 --'
fi