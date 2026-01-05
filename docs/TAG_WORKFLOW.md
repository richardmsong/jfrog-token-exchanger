# Tag and Version Branch Workflow

This document describes the tag workflow implementation for the jfrog-token-exchanger project.

## Overview

When a new version tag is created (e.g., `v1.2.3`), the following should happen:

1. **Lock kustomization.yaml to the tag version**: The `config/manager/kustomization.yaml` file should be updated to reference the specific Docker image tag
2. **Update major.minor branch**: Create or update a branch like `v1.2` to point to the latest patch version
3. **Update major branch**: Create or update a branch like `v1` to point to the latest minor/patch version

## Implementation Options

### Option 1: Automated GitHub Actions Workflow (Recommended)

Create `.github/workflows/tag-release.yml` with the following content:

```yaml
name: Tag Release

on:
  push:
    tags:
      - 'v*.*.*'

permissions:
  contents: write

jobs:
  update-version-branches:
    name: Update Version Branches and Kustomization
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
          token: ${{ secrets.GITHUB_TOKEN }}

      - name: Configure Git
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"

      - name: Extract version information
        id: version
        run: |
          TAG=${GITHUB_REF#refs/tags/}
          VERSION=${TAG#v}
          MAJOR=$(echo $VERSION | cut -d. -f1)
          MINOR=$(echo $VERSION | cut -d. -f2)
          PATCH=$(echo $VERSION | cut -d. -f3)

          echo "tag=$TAG" >> $GITHUB_OUTPUT
          echo "version=$VERSION" >> $GITHUB_OUTPUT
          echo "major=$MAJOR" >> $GITHUB_OUTPUT
          echo "minor=$MINOR" >> $GITHUB_OUTPUT
          echo "patch=$PATCH" >> $GITHUB_OUTPUT
          echo "major_minor=${MAJOR}.${MINOR}" >> $GITHUB_OUTPUT

      - name: Update kustomization.yaml with tag
        run: |
          TAG="${{ steps.version.outputs.tag }}"

          # Update config/manager/kustomization.yaml
          if grep -q "newTag:" config/manager/kustomization.yaml; then
            sed -i "s/newTag:.*/newTag: $TAG/" config/manager/kustomization.yaml
          else
            # Add newTag after newName
            sed -i "/newName: ghcr.io\/richardmcsong\/jfrog-token-exchanger/a\  newTag: $TAG" config/manager/kustomization.yaml
          fi

          # Commit the change
          git add config/manager/kustomization.yaml
          if git diff --cached --quiet; then
            echo "No changes to kustomization.yaml"
          else
            git commit -m "chore: update kustomization to use $TAG"
            git tag -f "$TAG"
            git push origin "$TAG" --force
          fi

      - name: Update or create major.minor branch
        run: |
          BRANCH="v${{ steps.version.outputs.major_minor }}"
          TAG="${{ steps.version.outputs.tag }}"

          # Check if branch exists remotely
          if git ls-remote --heads origin "$BRANCH" | grep -q "$BRANCH"; then
            echo "Branch $BRANCH exists, updating it"
            git checkout -b "$BRANCH" "origin/$BRANCH"
            git reset --hard "$TAG"
          else
            echo "Creating new branch $BRANCH"
            git checkout -b "$BRANCH" "$TAG"
          fi

          git push origin "$BRANCH" --force

      - name: Update or create major branch
        run: |
          MAJOR="${{ steps.version.outputs.major }}"
          BRANCH="v$MAJOR"
          TAG="${{ steps.version.outputs.tag }}"

          # Skip v0 major branch
          if [ "$MAJOR" = "0" ]; then
            echo "Skipping major branch for v0.x.x"
            exit 0
          fi

          # Check if branch exists remotely
          if git ls-remote --heads origin "$BRANCH" | grep -q "$BRANCH"; then
            echo "Branch $BRANCH exists, updating it"
            git fetch origin "$BRANCH"
            git checkout -b "$BRANCH" "origin/$BRANCH"
            git reset --hard "$TAG"
          else
            echo "Creating new branch $BRANCH"
            git checkout -b "$BRANCH" "$TAG"
          fi

          git push origin "$BRANCH" --force
```

**Note**: Due to Claude Code's GitHub App permissions, this workflow file could not be directly created in `.github/workflows/`. You'll need to manually create it or merge it from the PR.

### Option 2: Manual Script Execution

A script is provided at `scripts/update-version-branches.sh` that can be run manually:

```bash
# Make the script executable
chmod +x scripts/update-version-branches.sh

# Run for a specific tag
./scripts/update-version-branches.sh v1.2.3
```

This is useful for:
- One-off version releases
- Testing the workflow before automating
- Retroactively updating old tags

## Example Workflow

When you push tag `v1.2.3`:

1. **Kustomization update**: `config/manager/kustomization.yaml` is updated:
   ```yaml
   images:
   - name: controller
     newName: ghcr.io/richardmcsong/jfrog-token-exchanger
     newTag: v1.2.3
   ```

2. **Branch `v1.2` creation/update**: Points to the `v1.2.3` tag
   - If you later push `v1.2.4`, this branch will be updated to point to `v1.2.4`

3. **Branch `v1` creation/update**: Points to the `v1.2.3` tag
   - If you later push `v1.3.0`, this branch will be updated to point to `v1.3.0`

## Benefits

- **Reproducible deployments**: Specific version tags lock to specific image versions
- **Easy minor/patch tracking**: Users can track major or minor versions without pinning to patches
- **Automated maintenance**: Version branches are automatically kept up-to-date

## Notes

- The `v0` major branch is intentionally skipped (common convention for pre-1.0 releases)
- Force pushes are used for version branches (this is expected behavior for tracking branches)
- The workflow requires `contents: write` permission to update branches and tags
