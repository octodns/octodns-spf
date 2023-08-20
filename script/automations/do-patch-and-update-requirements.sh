#!/bin/bash
# patches for use with the script can likely be created with the following
# git format-patch -1 [sha]

set -e

PATCH="$HOME/octodns/octodns-template/tmp/0001-Update-CI-python-versions-remove-3.7.patch"
BRANCH="python-versions"

# make sure we're on main to start
(test $(git rev-parse --abbrev-ref HEAD) != "main" && echo "on branch" && exit 1 || exit 0)

# make sure we're completely up to date with origin
git pull

# create our branch
git checkout -b $BRANCH

# make our patch
patch -p1 --no-backup-if-mismatch < $PATCH

# add and comment changes
git add -p .github/
git commit -m "update CI python versions, remove 3.7"

git add -p setup.py
git commit -m "update setup.py requirement versions now that 3.7 is gone"

# update requirements
./script/update-requirements

# re-bootstrap to make sure those versions are installed
./script/bootstrap

# make any formatting changes
./script/format

# show any lint errors
./script/lint

# add and comment requirements changes
git add -p requirements*.txt
git commit -m "update requirements*.txt"

# if there's any formatting changes add them and then commit them, there
# shouldn't be anything else happening here, if you make non-formatting changes
# for some reason commit those manually
if ! git status --porcelain; then
  git add -p
  git commit -m "updated black formatting"
fi

# push our current branch
git push -u origin $BRANCH

# and open a PR, this assumes your local handle matches your github handle, if
# not set USER= before running the script
hub pull-request --browse --file /tmp/body.txt -b main -h $BRANCH -a $USER
