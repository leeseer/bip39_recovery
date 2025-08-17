#!/bin/bash

# Example usage of the BIP39 Recovery Tool

echo "BIP39 Recovery Tool - Example Usage"
echo "==================================="

# Example 1: Basic usage with known words
echo "Example 1: Basic usage with known words"
echo "--------------------------------------"
echo "Command:"
echo "bip39_recovery --total-words 12 --fixed-words 8 \\"
echo "  --known-words \"abandon,ability,able,about,absent,absorb,abstract,absurd,example,word,list,here\" \\"
echo "  --address \"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\""
echo ""

# Example 2: Using files for input
echo "Example 2: Using files for input"
echo "--------------------------------"
echo "Command:"
echo "bip39_recovery --total-words 12 --fixed-words 8 \\"
echo "  --seed-words-file example_words.txt \\"
echo "  --address-file example_address.txt"
echo ""

# Example 3: With GPU acceleration
echo "Example 3: With GPU acceleration"
echo "--------------------------------"
echo "Command:"
echo "bip39_recovery --gpu --total-words 12 --fixed-words 8 \\"
echo "  --known-words \"abandon,ability,able,about,absent,absorb,abstract,absurd,example,word,list,here\" \\"
echo "  --address \"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\""
echo ""

# Example 4: With custom derivation path
echo "Example 4: With custom derivation path"
echo "--------------------------------------"
echo "Command:"
echo "bip39_recovery --total-words 12 --fixed-words 8 \\"
echo "  --known-words \"abandon,ability,able,about,absent,absorb,abstract,absurd,example,word,list,here\" \\"
echo "  --address \"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\" \\"
echo "  --path \"m/49'/0'/0'/0/0\""
echo ""

echo "For more information, see the README.md file."