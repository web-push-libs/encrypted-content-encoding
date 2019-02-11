#!/usr/bin/env bash

set -e

root=$(cd $(dirname "$0"); pwd -P)
cd "$root"
sub='{ s/^.*["'"'"']\([0-9]*\.[0-9]*\.[0-9]*\)["'"'"'].*$/\1/;p; }'
old1=$(sed -n -e '/version *=/'"$sub"'' python/setup.py)
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
        sed -i~ -e '/version *=/'"$sub" python/setup.py
        sed -i~ -e '/"version" *:/'"$sub" nodejs/package.json
        ;;

    =)
        new="$old1"
        ;;
    *)
        echo "Publish current version: $0 =" 1>&2
        echo "Increment version and publish: $0 +" 1>&2
        exit 2
esac

pushd "$root"/python
python setup.py sdist
twine upload dist/http_ece-"$new".tar.gz
popd

pushd "$root"/nodejs
npm publish
popd

if [[ "$1" == "+" ]]; then
    git commit -m "Update version to $new" python/setup.py nodejs/package.json
fi
git tag -a v"$new" -m "Release version $new"
git push origin v"$new"
