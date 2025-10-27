#!/bin/bash

# Function to find bugs
find_bugs() {
    local url=$1
    echo "Finding bugs for $url..."
    
    # Use curl to fetch the webpage
    curl -s "$url" > webpage.html
    
    # Parse the HTML to find potential bugs
    grep -E "<script>|<img>|<iframe>" webpage.html > bugs.txt
    
    echo "Bugs found:"
    cat bugs.txt
}

# Function to find assets
find_assets() {
    local url=$1
    echo "Finding assets for $url..."
    
    # Use wget to download the webpage
    wget -q "$url"
    
    # Find all image files in the downloaded directory
    find . -type f -name "*.jpg" -o -name "*.png" -o -name "*.gif" > assets.txt
    
    echo "Assets found:"
    cat assets.txt
}

# Function to find subdomains
find_subdomains() {
    local url=$1
    echo "Finding subdomains for $url..."
    
    # Use dig to perform DNS lookup
    dig "$url" +short > subdomains.txt
    
    echo "Subdomains found:"
    cat subdomains.txt
}

# Main function
main() {
    local url=$1
    
    if [ -z "$url" ]; then
        echo "Please provide a website URL."
        exit 1
    fi
    
    echo "Analyzing $url..."
    
    find_bugs "$url"
    find_assets "$url"
    find_subdomains "$url"
    
    echo "Analysis complete."
}

# Call the main function with the provided URL
main "$1"
