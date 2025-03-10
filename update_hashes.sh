#!/bin/bash

# Create data directory


# Download malware hashes (ZIP format)
if curl -fSsL "https://bazaar.abuse.ch/export/txt/sha256/full/" -o temp_hashes.zip; then
    echo "✅ Downloaded hash archive successfully"
    
    # Extract and process hashes
    if unzip -p temp_hashes.zip | grep -a -v '^#' | awk '{print $1}' > data/known_hashes.txt; then
        echo "Total malware hashes: $(wc -l < data/known_hashes.txt)"
    else
        echo "❌ Extraction failed. Using backup hash."
        echo "d3d9446802a44259755d38e6d163e820b1d5c23d4a83e52e6a89c5a72162e7f0" > data/known_hashes.txt
    fi
    
    # Cleanup
    rm -f temp_hashes.zip
    
else
    echo "❌ Download failed. Using backup hash."
    echo "d3d9446802a44259755d38e6d163e820b1d5c23d4a83e52e6a89c5a72162e7f0" > data/known_hashes.txt
fi

# Final verification
echo -e "\nFirst 3 hashes:"
head -n 3 data/known_hashes.txt
