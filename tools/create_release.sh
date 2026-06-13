#!/bin/bash

SEMTAG='./tools/semtag'
ACTION=${1:-patch}

git fetch origin --tags

RELEASE_VERSION="$($SEMTAG final -s $ACTION -o)"

echo "Next release version: $RELEASE_VERSION"

if test -f "pyproject.toml"; then
  PROJECT_VERSION=$(echo $RELEASE_VERSION | sed 's/^v//')
  python src/utils/update_project_version.py "$PROJECT_VERSION"

  # Ensure CHANGELOG.md carries a section for this version BEFORE the tag is
  # created, in the SAME bump commit that gets tagged. The downstream
  # auto-generate-release workflow (taiki-e/create-gh-release-action with
  # allow-missing-changelog=false) extracts release notes from the tagged
  # commit and fails hard if the section is absent.
  if test -f "CHANGELOG.md" && ! grep -q "## \[$PROJECT_VERSION\]" CHANGELOG.md; then
    PREV_TAG=$(git describe --tags --abbrev=0 2>/dev/null)
    if [ -n "$PREV_TAG" ]; then
      RANGE="$PREV_TAG..HEAD"
    else
      RANGE="HEAD"
    fi

    NOTES=$(git log --no-merges --pretty=format:'- %s' "$RANGE")
    if [ -z "$NOTES" ]; then
      NOTES="- Release $RELEASE_VERSION"
    fi

    RELEASE_DATE=$(date +%Y-%m-%d)
    printf '## [%s] - %s\n\n%s\n\n' "$PROJECT_VERSION" "$RELEASE_DATE" "$NOTES" > /tmp/changelog_section.txt

    # Insert the new section directly above the first existing "## [" heading,
    # keeping the file header intact and newest-version-first ordering.
    awk 'NR==FNR { section = section $0 ORS; next }
         !inserted && /^## \[/ { printf "%s", section; inserted = 1 }
         { print }
         END { if (!inserted) printf "%s", section }' \
      /tmp/changelog_section.txt CHANGELOG.md > CHANGELOG.md.tmp
    mv CHANGELOG.md.tmp CHANGELOG.md
    git add CHANGELOG.md
  fi

  git config --global user.name 'github-actions'
  git config --global user.email 'github-actions@users.noreply.github.com'
  git add pyproject.toml
  git commit -m "Bump version to $RELEASE_VERSION"
  git push
fi

$SEMTAG final -s $ACTION -v "$RELEASE_VERSION"
