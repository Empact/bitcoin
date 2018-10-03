#!/bin/sh
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# This script checks for commits beginning with: tested-change:
# If found, looks for a script between the lines -BEGIN TEST SCRIPT- and
# -END TEST SCRIPT-. If no ending is found, it reads until the end of the
# commit message.

# The make should succeed and the resulting script should fail. This is used
# to demonstrate that an included test fails before a given code change.

export LC_ALL=C
if test "x$1" = "x"; then
    echo "Usage: $0 <commit>..."
    exit 1
fi

ROLL_BACK () {
  git checkout --quiet HEAD^ -- "$1" || exit 1
}

ROLL_BACK_EXCEPT () {
  git checkout --quiet HEAD^ -- ":(exclude)$1" || exit 1
}

RUN_MAKE () {
  make $MAKEJOBS $GOAL || ( echo "Build failure. Verbose build follows." && make $GOAL V=1 ; false )
}

RET=0
PREV_BRANCH=`git name-rev --name-only HEAD`
PREV_HEAD=`git rev-parse HEAD`
if git rev-list -n 1 --pretty="%s" HEAD | grep -q "^tested-change:"; then
    SCRIPT="`git rev-list --format=%b -n1 HEAD | sed '/^-BEGIN TEST SCRIPT-$/,/^-END TEST SCRIPT-$/{//!b};d'`"
    if test "x$SCRIPT" = "x"; then
        echo "Error: missing script for: $PREV_HEAD"
        echo "Failed"
        RET=1
    else
        echo "Running script for: $PREV_HEAD"
        echo "$SCRIPT"
        eval "$SCRIPT" && (echo "Succeeded, expected failure"; false) || RET=1
    fi
    git reset --quiet --hard HEAD
fi
git checkout --quiet $PREV_BRANCH 2>/dev/null || git checkout --quiet $PREV_HEAD
exit $RET
