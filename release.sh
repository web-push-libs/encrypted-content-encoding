#!/usr/bin/env bash

set -e

root=$(cd $(dirname "$0"); pwd -P)
cd "$root"
python_metadata=python/pyproject.toml

# Push to the canonical repository, not a personal fork.
remote=${RELEASE_REMOTE:-$(git remote -v | awk '/web-push-libs\/encrypted-content-encoding/ { print $1; exit }')}
remote=${remote:-origin}
sub='{ s/^.*["'"'"']\([0-9]*\.[0-9]*\.[0-9]*\)["'"'"'].*$/\1/;p; }'
old1=$(sed -n -e '/version *=/'"$sub"'' "$python_metadata")
old2=$(sed -n -e '/"version" *:/'"$sub"'' nodejs/package.json)
if [[ "$old1" != "$old2" ]]; then
    echo "Versions aren't the same: $old1 != $old2" 1>&2
    exit 1
fi

case "$1" in
    +)
        IFS=. v=($old1)
        new="${v[0]}.${v[1]}.$((${v[2]} + 1))"

        sub='s/\(["'"'"']\)'"$old1"'["'"'"']/\1'"$new"'\1/'
        sed -i~ -e '/version *=/'"$sub" "$python_metadata"
        sed -i~ -e '/"version" *:/'"$sub" nodejs/package.json
        (cd nodejs && npm install --package-lock-only --ignore-scripts >/dev/null)
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

pushd "$root"/python
pybuild --sdist --wheel
twine upload dist/http_ece-"$new".tar.gz dist/http_ece-"$new"-*.whl
popd

pushd "$root"/nodejs
npm publish
popd

if [[ "$1" == "+" ]]; then
    git commit -m "Update version to $new" "$python_metadata" nodejs/package.json nodejs/package-lock.json
    git push "$remote" HEAD
fi
git tag -a v"$new" -m "Release version $new"
git push "$remote" v"$new"
