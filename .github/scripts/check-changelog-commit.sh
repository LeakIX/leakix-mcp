#!/usr/bin/env bash
# Verify that CHANGELOG.md changes are in their own dedicated commit.
#
# Usage: check-changelog-commit.sh <base-sha>
set -euo pipefail

base="${1:?Usage: check-changelog-commit.sh <base-sha>}"

for commit in $(git log --format=%H "${base}..HEAD"); do
    files=$(git diff-tree --no-commit-id --name-only -r "$commit")
    if echo "$files" | grep -q "^CHANGELOG.md$"; then
        file_count=$(echo "$files" | wc -l | tr -d ' ')
        if [ "$file_count" -gt 1 ]; then
            echo "::error::Commit $commit modifies CHANGELOG.md alongside other files."
            echo "CHANGELOG.md changes must be in their own dedicated commit."
            exit 1
        fi
    fi
done

echo "Changelog check passed."
