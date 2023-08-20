#!/bin/bash

set -e

if [ -z "$1" ]; then
  if ! git diff --no-ext-diff --quiet --exit-code; then
    echo "local changes"
    exit 1
  fi

  if test $(git rev-parse --abbrev-ref HEAD) != "main"; then
    echo "on branch"
    exit 1
  fi

  git pull
  git checkout -b isort
fi


MODULE=$(basename "$PWD" | sed 's/-/_/')

sed -e s/octodns_spf/$MODULE/ ~/octodns/octodns-template/pyproject.toml > pyproject.toml

TMP=$(mktemp)
awk "/build.*/ {print; print \"            # >=5.12.0 does not support python 3.7, we still do\"; print \"            'isort==5.11.5',\"; next }1" ./setup.py > $TMP
mv $TMP setup.py

perl -i -p0e 's/export PYTHONPATH.*\npytest/pytest/se' script/coverage
perl -i -p0e 's/export PYTHONPATH.*\npytest/pytest/se' script/test

cp ~/octodns/octodns-template/script/format script/format

source env/bin/activate

./script/update-requirements
deactivate
rm -rf env/
./script/bootstrap

source env/bin/activate

git add .
git commit -m "Add isort, use pyproject.toml for isort and black" --no-verify

./script/format

git add .
git commit -m "isort formatting"

echo "# Commit for isort formatting changes" >> .git-blame-ignore-revs
git rev-parse --verify HEAD >> .git-blame-ignore-revs

git add .
git commit -m "ignore isort commit in blame" --no-verify

git pob

hub pull-request --file /tmp/body.txt -b main -h isort -a ross
