#!/bin/bash
set -e

# Script to update kustomization.yaml and create/update version branches
# Usage: ./scripts/update-version-branches.sh <tag>
# Example: ./scripts/update-version-branches.sh v1.2.3

if [ -z "$1" ]; then
  echo "Usage: $0 <tag>"
  echo "Example: $0 v1.2.3"
  exit 1
fi

TAG=$1
VERSION=${TAG#v}
MAJOR=$(echo $VERSION | cut -d. -f1)
MINOR=$(echo $VERSION | cut -d. -f2)
PATCH=$(echo $VERSION | cut -d. -f3)
MAJOR_MINOR="${MAJOR}.${MINOR}"

echo "Processing tag: $TAG"
echo "Version: $VERSION (Major: $MAJOR, Minor: $MINOR, Patch: $PATCH)"

# Update kustomization.yaml with tag
echo "Updating config/manager/kustomization.yaml..."
if grep -q "newTag:" config/manager/kustomization.yaml; then
  sed -i "s/newTag:.*/newTag: $TAG/" config/manager/kustomization.yaml
else
  # Add newTag after newName
  sed -i "/newName: ghcr.io\/richardmcsong\/jfrog-token-exchanger/a\  newTag: $TAG" config/manager/kustomization.yaml
fi

# Show the change
echo "Updated kustomization.yaml:"
grep -A 2 "name: controller" config/manager/kustomization.yaml

# Commit the change if there are changes
if ! git diff --quiet config/manager/kustomization.yaml; then
  git add config/manager/kustomization.yaml
  git commit -m "chore: update kustomization to use $TAG"
  git tag -f "$TAG"
  echo "Committed kustomization update and updated tag $TAG"
else
  echo "No changes to kustomization.yaml"
fi

# Update or create major.minor branch
BRANCH="v${MAJOR_MINOR}"
echo ""
echo "Processing branch: $BRANCH"

if git show-ref --verify --quiet "refs/heads/$BRANCH"; then
  echo "Branch $BRANCH exists locally, updating it"
  git checkout "$BRANCH"
  git reset --hard "$TAG"
elif git ls-remote --heads origin "$BRANCH" | grep -q "$BRANCH"; then
  echo "Branch $BRANCH exists remotely, checking out and updating"
  git checkout -b "$BRANCH" "origin/$BRANCH"
  git reset --hard "$TAG"
else
  echo "Creating new branch $BRANCH"
  git checkout -b "$BRANCH" "$TAG"
fi

echo "Pushing $BRANCH to origin..."
git push origin "$BRANCH" --force

# Update or create major branch (skip v0)
if [ "$MAJOR" != "0" ]; then
  MAJOR_BRANCH="v${MAJOR}"
  echo ""
  echo "Processing branch: $MAJOR_BRANCH"

  git checkout "$TAG"

  if git show-ref --verify --quiet "refs/heads/$MAJOR_BRANCH"; then
    echo "Branch $MAJOR_BRANCH exists locally, updating it"
    git checkout "$MAJOR_BRANCH"
    git reset --hard "$TAG"
  elif git ls-remote --heads origin "$MAJOR_BRANCH" | grep -q "$MAJOR_BRANCH"; then
    echo "Branch $MAJOR_BRANCH exists remotely, checking out and updating"
    git checkout -b "$MAJOR_BRANCH" "origin/$MAJOR_BRANCH"
    git reset --hard "$TAG"
  else
    echo "Creating new branch $MAJOR_BRANCH"
    git checkout -b "$MAJOR_BRANCH" "$TAG"
  fi

  echo "Pushing $MAJOR_BRANCH to origin..."
  git push origin "$MAJOR_BRANCH" --force
else
  echo ""
  echo "Skipping major branch for v0.x.x"
fi

echo ""
echo "Done! Summary:"
echo "  - Updated kustomization.yaml to use $TAG"
echo "  - Updated/created branch v${MAJOR_MINOR}"
if [ "$MAJOR" != "0" ]; then
  echo "  - Updated/created branch v${MAJOR}"
fi
