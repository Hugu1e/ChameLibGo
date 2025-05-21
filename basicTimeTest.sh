#!/bin/bash

DICTORYS=(
    "scheme/CH"
    "scheme/IBCH"
    "scheme/PBCH"
)

REPEAT=1000

for dir in "${DICTORYS[@]}"; do
    if [ -d "$dir" ]; then
        echo "Contents of $dir:"
        for subdir in $(find "$dir" -mindepth 1 -type d); do
            echo "Test $subdir:"
            > testResult/"${subdir##*/}".txt
            echo "--------------------------------------------------------------------------"
            ( cd "$subdir" && go test -timeout 3600000s -repeat "${REPEAT}" )
        done
    fi
done

