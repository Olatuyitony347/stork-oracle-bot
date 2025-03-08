#!/bin/bash

while true; do
    node index.js | while read line; do
        echo "$line"
        if echo "$line" | grep -q "Validation process stopped"; then
            echo "Restarting script due to validation error..."
            break
        fi
    done
    sleep 5  # Wait 5 seconds before restarting
done

