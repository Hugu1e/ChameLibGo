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
            echo "--------------------------------------------------------------------------"
            ( cd "$subdir" && go test -repeat "${REPEAT}" )
        done
    fi
done

