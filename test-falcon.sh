#!/bin/bash
# Quick test script for Falcon-512 in Docker container

# First, find where the provider actually is
PROVIDER_PATH="/code/build/_build/lib/ossl-modules"
if [ ! -f "$PROVIDER_PATH/oqsprovider.so" ]; then
    # Try alternative locations
    if [ -f "/code/build/lib/ossl-modules/oqsprovider.so" ]; then
        PROVIDER_PATH="/code/build/lib/ossl-modules"
    elif [ -f "/code/_build/lib/ossl-modules/oqsprovider.so" ]; then
        PROVIDER_PATH="/code/_build/lib/ossl-modules"
    else
        echo "ERROR: Cannot find oqsprovider.so"
        echo "Searching..."
        find /code -name "oqsprovider.so" 2>/dev/null
        exit 1
    fi
fi

echo "Using provider path: $PROVIDER_PATH"
ls -lh "$PROVIDER_PATH/oqsprovider.so"

# Test with explicit provider loading
echo ""
echo "Testing Falcon-512 key generation..."
openssl genpkey -provider-path "$PROVIDER_PATH" \
    -provider default -provider oqsprovider \
    -algorithm falcon512 \
    -out /tmp/test.key

if [ $? -eq 0 ]; then
    echo "SUCCESS! Key generated:"
    ls -lh /tmp/test.key
    echo ""
    echo "Key info:"
    openssl pkey -provider-path "$PROVIDER_PATH" \
        -provider default -provider oqsprovider \
        -in /tmp/test.key -text -noout | head -20
else
    echo "FAILED to generate key"
    exit 1
fi

