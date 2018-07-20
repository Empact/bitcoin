#!/usr/bin/env bash
#
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C

# update first to install required ruby dependency
travis_retry brew update
travis_retry brew install shellcheck
# git --perl-regexp is used in test/lint/check-doc.py
travis_retry brew reinstall --with-pcre2 git
travis_retry brew upgrade python
travis_retry pip3 install flake8 --user
export PATH="$PATH:~/Library/Python/3.7/bin"
