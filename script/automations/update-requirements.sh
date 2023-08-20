#!/bin/bash

set -e

if [ -n "$1" ]; then
  MSG="$1"
else
  MSG="update requirements*.txt"
fi

# make sure we don't have uncommited changes
([[ `git status --porcelain` ]] && echo "local changes" && exit 1 || exit 0)

# make sure we're on main to start
(test $(git rev-parse --abbrev-ref HEAD) != "main" && echo "on branch" && exit 1 || exit 0)

# make sure we're completely up to date with origin
git pull

# create our branch
BRANCH=update-requirements
git checkout -b $BRANCH

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
git commit -m "$1"

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
