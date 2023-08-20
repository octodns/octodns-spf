#!/bin/bash
# patches for use with the script can likely be created with the following
# git format-patch -1 [sha]

set -e

PATCH="$1"
BRANCH="$2"
COMMIT_MESSAGE="$3"
PR_MESSAGE="$4"

if [[ -z "$PR_MESSAGE" || ! -e "$PR_MESSAGE" ]]; then
  echo "incorrect usage"
  exit 1
fi

# make sure we don't have uncommited changes
([[ `git status --porcelain` ]] && echo "local changes" && exit 1 || exit 0)

# make sure we're on main to start
(test $(git rev-parse --abbrev-ref HEAD) != "main" && echo "on branch" && exit 1 || exit 0)

# make sure we're completely up to date with origin
git pull

# create our branch
git checkout -b $BRANCH

# make our patch
patch -p1 --no-backup-if-mismatch < $PATCH

# add and comment changes
# TODO: this doesn't support newly added files...
git add -p
git commit -m "$COMMIT_MESSAGE"

# push our current branch
git push -u origin $BRANCH

# and open a PR, this assumes your local handle matches your github handle, if
# not set USER= before running the script
hub pull-request --browse --file $PR_MESSAGE -b main -h $BRANCH -a $USER
