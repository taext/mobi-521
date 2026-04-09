#!/usr/bin/env bash
# Test script for clipboard encryption/decryption

set -e

echo "=== Testing mobi521 clipboard functionality ==="
echo ""

# Generate a test key if needed
if [ ! -f test_key.m521 ]; then
    echo "Generating test key..."
    ./target/release/mobi521 keygen -o test_key.m521
    PUBKEY=$(grep "^# public key:" test_key.m521 | awk '{print $4}')
    echo "Public key: $PUBKEY"
    echo ""
fi

# Extract the public key
PUBKEY=$(grep "^# public key:" test_key.m521 | awk '{print $4}')

echo "Test 1: Clipboard → Clipboard (no files)"
echo "-----------------------------------------"
echo "1. Copy some text to your clipboard"
echo "2. Run: ./target/release/mobi521 encrypt -r $PUBKEY"
echo "3. Ciphertext should be copied to clipboard"
echo "4. Run: ./target/release/mobi521 decrypt -i test_key.m521"
echo "5. Original plaintext should be back in clipboard"
echo ""

echo "Test 2: File → stdout (input file, no -o)"
echo "------------------------------------------"
echo "1. Run: echo 'Hello from file' > test_input.txt"
echo "2. Run: ./target/release/mobi521 encrypt -r $PUBKEY test_input.txt"
echo "3. Encrypted text should be printed to stdout (NOT clipboard)"
echo "4. Run: ./target/release/mobi521 decrypt -i test_key.m521 test_encrypted.txt"
echo "5. Plaintext should be printed to stdout (NOT clipboard)"
echo ""

echo "Test 3: File → File (both specified)"
echo "------------------------------------"
echo "1. Run: ./target/release/mobi521 encrypt -r $PUBKEY test_input.txt -o test_encrypted.txt"
echo "2. Run: ./target/release/mobi521 decrypt -i test_key.m521 test_encrypted.txt -o test_output.txt"
echo "3. Check: cat test_output.txt"
echo ""

echo "Test 4: Clipboard input, file output"
echo "------------------------------------"
echo "1. Copy some text to clipboard"
echo "2. Run: ./target/release/mobi521 encrypt -r $PUBKEY -o test_encrypted.txt"
echo "3. Encrypted text should be in test_encrypted.txt"
echo ""

echo "Manual test instructions above. To run a full automated test (Wayland with wl-clipboard):"
echo "  ./test_clipboard.sh auto"
echo ""

if [ "$1" = "auto" ]; then
    if ! command -v wl-copy &> /dev/null; then
        echo "Error: wl-copy not found. Install with: nix develop"
        exit 1
    fi

    echo "Running automated tests..."
    echo ""

    # Test 1: Clipboard → Clipboard
    echo "Test 1: Clipboard → Clipboard"
    echo "------------------------------"
    TEST_TEXT="Secret message for clipboard encryption test"

    # Copy to clipboard
    echo -n "$TEST_TEXT" | wl-copy
    echo "  1. Copied test text to clipboard"

    # Encrypt from clipboard to clipboard
    ./target/release/mobi521 encrypt -r "$PUBKEY" 2>&1 | grep -q "reading from clipboard"
    echo "  2. Encrypted from clipboard to clipboard"

    # Decrypt from clipboard to clipboard
    ./target/release/mobi521 decrypt -i test_key.m521 2>&1 | grep -q "reading from clipboard"
    echo "  3. Decrypted from clipboard to clipboard"

    # Get decrypted text
    DECRYPTED=$(wl-paste)
    echo "  4. Retrieved decrypted text from clipboard"

    # Compare
    if [ "$TEST_TEXT" = "$DECRYPTED" ]; then
        echo "  ✓ SUCCESS: Clipboard → Clipboard works!"
    else
        echo "  ✗ FAILED: Texts don't match"
        echo "    Original:  $TEST_TEXT"
        echo "    Decrypted: $DECRYPTED"
        exit 1
    fi
    echo ""

    # Test 2: File → stdout
    echo "Test 2: File → stdout"
    echo "---------------------"
    echo "Hello from file test" > test_input.txt
    echo "  1. Created test input file"

    # Encrypt file to stdout
    ENCRYPTED=$(./target/release/mobi521 encrypt -r "$PUBKEY" test_input.txt)
    echo "  2. Encrypted file to stdout"

    # Save to file for decryption
    echo "$ENCRYPTED" > test_encrypted.txt

    # Decrypt file to stdout
    DECRYPTED=$(./target/release/mobi521 decrypt -i test_key.m521 test_encrypted.txt)
    echo "  3. Decrypted file to stdout"

    if [ "Hello from file test" = "$DECRYPTED" ]; then
        echo "  ✓ SUCCESS: File → stdout works!"
    else
        echo "  ✗ FAILED: Decryption failed"
        echo "    Expected: Hello from file test"
        echo "    Got: $DECRYPTED"
        exit 1
    fi
    echo ""

    # Test 3: File → File
    echo "Test 3: File → File"
    echo "-------------------"
    echo "File to file test" > test_input2.txt
    echo "  1. Created test input file"

    ./target/release/mobi521 encrypt -r "$PUBKEY" test_input2.txt -o test_encrypted2.txt 2>&1
    echo "  2. Encrypted to output file"

    ./target/release/mobi521 decrypt -i test_key.m521 test_encrypted2.txt -o test_output2.txt 2>&1
    echo "  3. Decrypted to output file"

    RESULT=$(cat test_output2.txt)
    if [ "File to file test" = "$RESULT" ]; then
        echo "  ✓ SUCCESS: File → File works!"
    else
        echo "  ✗ FAILED: File output doesn't match"
        exit 1
    fi
    echo ""

    # Cleanup
    rm -f test_input.txt test_input2.txt test_encrypted.txt test_encrypted2.txt test_output2.txt

    echo "=========================================="
    echo "All tests passed! ✓"
    echo "=========================================="
fi
