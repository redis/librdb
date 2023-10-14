#!/bin/bash

for unwrap_json_file in *.json; do
    tmp_file=wrapped_$unwrap_json_file
    # Wrap the unwrapped JSON file with curly braces to make it valid JSON
    echo '{' > $tmp_file
    cat "$unwrap_json_file" >> $tmp_file
    echo '}' >> $tmp_file

    # Use jq to check if the JSON is valid
    if jq empty $tmp_file &> /dev/null; then
        echo "Validation succeeded for $unwrap_json_file"
    else
        echo "Validation failed for $unwrap_json_file"
        exit 1
    fi

    # Clean up the temporary wrapped file
    rm $tmp_file
done
exit 0