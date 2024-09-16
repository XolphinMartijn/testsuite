#!/bin/bash

# Directory to search for .pem files
directory="pem"

# Function to POST the content of a PEM file
post_pem_content() {
    local file_content
    file_content=$(<"$1")
    local b64_content
    b64_content=$(echo "$file_content")
    
    response=$(curl -s -X POST http://dev.pkimet.al/lintcert \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "b64input=$b64_content")
    
}

pem_count=0
pkimetal_count=0

# Find and iterate through all .pem files in the directory recursively
find "$directory" -type f -name "*.pem" | while read -r file; do
    
    pem_count=$((pem_count + 1))

    post_pem_content "$file"

    # Check if the response is a valid JSON
    if echo "$response" | jq . >/dev/null 2>&1; then

        if echo "$response" | jq -e '.[] | select(.Severity == "fatal")' >/dev/null; then
            echo "Fatal severity found in response: $response"
            exit -1
        fi

        # Count the number of pkimetal linter is correctly invoked. This should match the pem_count
        pkimetal_count=$((pkimetal_count + $(echo "$response" | jq '[.[] | select(.Linter == "pkimetal")] | length')))
        
        # Collect the total number of warnings and errors per finding
        echo "$response" | jq -c '.[]' | while read -r finding; do
            severity=$(echo "$finding" | jq -r '.Severity')
            key=$(echo "$finding" | jq -r '.Finding')

            if [ "$severity" = "warning" ]; then
                warnings+=($key)
            elif [ "$severity" = "error" ]; then
                errors+=($key)
            fi
        done

    else
        echo "Invalid JSON response:"
        echo "$response"
        exit -1
    fi

    # Unset the response variable to avoid any confusion
    unset response

done

if [ "$pem_count" -ne "$pkimetal_count" ]; then
    echo "Mismatch between number of .pem files and number of pkimetal invocations"
    exit -1
fi

echo "${warnings[@]}"

declare -A warnings_count

# Count occurrences of each warning
for element in "${warnings[@]}"; do
    ((warnings_count["$element"]++))
done

# Print each unique element and its count
echo "Count of each unique item:"
for key in "${!warnings_count[@]}"; do
    echo "$key: ${warnings_count[$key]}"
done
