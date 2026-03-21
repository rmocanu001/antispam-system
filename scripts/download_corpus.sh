#!/bin/bash
# Download SpamAssassin Public Corpus for testing
# Source: https://spamassassin.apache.org/old/publiccorpus/

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CORPUS_DIR="$PROJECT_DIR/testdata/corpus"
DOWNLOAD_DIR="$CORPUS_DIR/downloads"

HAM_DIR="$CORPUS_DIR/ham"
SPAM_DIR="$CORPUS_DIR/spam"

BASE_URL="https://spamassassin.apache.org/old/publiccorpus"

# Corpus archives
ARCHIVES=(
    "20030228_easy_ham.tar.bz2"
    "20030228_easy_ham_2.tar.bz2"
    "20030228_hard_ham.tar.bz2"
    "20030228_spam.tar.bz2"
    "20030228_spam_2.tar.bz2"
)

echo "=== SpamAssassin Corpus Downloader ==="
echo "Target directory: $CORPUS_DIR"

# Create directories
mkdir -p "$DOWNLOAD_DIR" "$HAM_DIR" "$SPAM_DIR"

# Download archives
for archive in "${ARCHIVES[@]}"; do
    if [ -f "$DOWNLOAD_DIR/$archive" ]; then
        echo "Already downloaded: $archive"
    else
        echo "Downloading: $archive ..."
        curl -L -o "$DOWNLOAD_DIR/$archive" "$BASE_URL/$archive" || {
            echo "WARNING: Failed to download $archive, trying wget..."
            wget -O "$DOWNLOAD_DIR/$archive" "$BASE_URL/$archive" || {
                echo "ERROR: Failed to download $archive"
                continue
            }
        }
    fi
done

# Extract and rename to .eml
echo ""
echo "Extracting and converting..."

counter=0

for archive in "${ARCHIVES[@]}"; do
    if [ ! -f "$DOWNLOAD_DIR/$archive" ]; then
        echo "Skipping missing archive: $archive"
        continue
    fi

    # Determine target directory based on archive name
    if echo "$archive" | grep -q "spam"; then
        target_dir="$SPAM_DIR"
        prefix="spam"
    else
        target_dir="$HAM_DIR"
        prefix="ham"
    fi

    # Extract to temp directory
    tmp_dir=$(mktemp -d)
    echo "Extracting $archive to $tmp_dir..."
    tar -xjf "$DOWNLOAD_DIR/$archive" -C "$tmp_dir" 2>/dev/null || {
        echo "WARNING: Failed to extract $archive"
        rm -rf "$tmp_dir"
        continue
    }

    # Move and rename files to .eml
    find "$tmp_dir" -type f ! -name "cmds" ! -name "*.bz2" | while read -r file; do
        counter=$((counter + 1))
        basename=$(basename "$file")
        # Create unique filename with .eml extension
        target_file="${target_dir}/${prefix}_${basename}.eml"
        if [ ! -f "$target_file" ]; then
            cp "$file" "$target_file"
        fi
    done

    rm -rf "$tmp_dir"
    echo "  -> Extracted to $target_dir"
done

# Count results
ham_count=$(find "$HAM_DIR" -name "*.eml" -type f | wc -l)
spam_count=$(find "$SPAM_DIR" -name "*.eml" -type f | wc -l)
total=$((ham_count + spam_count))

echo ""
echo "=== Corpus Ready ==="
echo "Ham emails:  $ham_count (in $HAM_DIR)"
echo "Spam emails: $spam_count (in $SPAM_DIR)"
echo "Total:       $total"
echo ""
echo "To run benchmark:"
echo "  go run cmd/benchmark/main.go --ham-dir $HAM_DIR --spam-dir $SPAM_DIR --limit 100"
