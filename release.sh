#!/usr/bin/env bash

set -euo pipefail

root=$(cd "$(dirname "$0")"; pwd -P)
cd "$root"
python_metadata=python/pyproject.toml
node_metadata=nodejs/package.json

# Push to the canonical repository, not a personal fork.
remote=${RELEASE_REMOTE:-$(git remote -v | awk '/web-push-libs\/encrypted-content-encoding/ { print $1; exit }')}
remote=${remote:-origin}

sub='{ s/^.*["'"'"']\([0-9]*\.[0-9]*\.[0-9]*\)["'"'"'].*$/\1/;p; }'
old1=$(sed -n -e '/^version *=/'"$sub"'' "$python_metadata")
old2=$(sed -n -e '/"version" *:/'"$sub"'' "$node_metadata")
if [[ "$old1" != "$old2" ]]; then
    echo "Versions aren't the same: $old1 != $old2" 1>&2
    exit 1
fi

case "${1:-}" in
    +)
        IFS=. read -r -a v <<< "$old1"
        new="${v[0]}.${v[1]}.$((v[2] + 1))"
        ;;
    =)
        new="$old1"
        ;;
    *)
        echo "Publish current version: $0 =" 1>&2
        echo "Increment version and publish: $0 +" 1>&2
        exit 2
esac

# Run Python tools through uvx when available, so they don't need to be installed.
if command -v uvx >/dev/null; then
    pybuild() { uvx --from build pyproject-build "$@"; }
    twine() { uvx twine "$@"; }
else
    pybuild() { python3 -m build "$@"; }
    twine() { python3 -m twine "$@"; }
fi

# Pre-flight checks, before anything irreversible happens.
if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    echo "Working tree has uncommitted changes" 1>&2
    exit 1
fi
if git rev-parse -q --verify "refs/tags/v$new" >/dev/null ||
   git ls-remote --exit-code --tags "$remote" "refs/tags/v$new" >/dev/null; then
    echo "Tag v$new already exists" 1>&2
    exit 1
fi
if ! npm whoami >/dev/null 2>&1; then
    echo "Not logged in to npm; run 'npm login' first" 1>&2
    exit 1
fi
echo "Releasing $new (pushing to remote '$remote')"

if [[ "$1" == "+" ]]; then
    # Undo the version bump if anything fails before publishing starts,
    # so the release can be retried from a clean tree.
    trap 'git checkout -- "$python_metadata" "$node_metadata" nodejs/package-lock.json' EXIT
    sub='s/\(["'"'"']\)'"$old1"'["'"'"']/\1'"$new"'\1/'
    sed -i -e '/^version *=/'"$sub" "$python_metadata"
    sed -i -e '/"version" *:/'"$sub" "$node_metadata"
    (cd nodejs && npm install --package-lock-only --ignore-scripts >/dev/null)
fi

# Build and validate both packages before publishing either of them.
pushd "$root"/nodejs
npm ci
npm test
npm pack --dry-run  # "prepack" builds the TypeScript declarations
popd

pushd "$root"/python
rm -rf dist build
pybuild --sdist --wheel
twine check dist/*
popd

trap - EXIT
twine upload python/dist/http_ece-"$new".tar.gz python/dist/http_ece-"$new"-*.whl
(cd nodejs && npm publish)

if [[ "$1" == "+" ]]; then
    git commit -m "Update version to $new" "$python_metadata" "$node_metadata" nodejs/package-lock.json
    git push "$remote" HEAD
fi
git tag -a v"$new" -m "Release version $new"
git push "$remote" v"$new"
