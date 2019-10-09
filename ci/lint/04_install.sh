#!/usr/bin/env bash
#
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C

if [ "$TRAVIS_OS_NAME" == "osx" ]; then
  # update first to install required ruby dependency
  ${CI_RETRY_EXE} brew update
  ${CI_RETRY_EXE} brew reinstall git -- --with-pcre2 # for  --perl-regexp
  ${CI_RETRY_EXE} brew install grep # gnu grep for --perl-regexp support
  PATH="$(brew --prefix grep)/libexec/gnubin:$PATH"
  ${CI_RETRY_EXE} brew install shellcheck
  ${CI_RETRY_EXE} brew upgrade python
  PATH="$(brew --prefix python)/bin:$PATH"
  export PATH
else
  SHELLCHECK_VERSION=v0.6.0
  ${CI_RETRY_EXE} curl --silent "https://storage.googleapis.com/shellcheck/shellcheck-${SHELLCHECK_VERSION}.linux.x86_64.tar.xz" | tar --xz -xf - --directory /tmp/
  PATH="/tmp/shellcheck-${SHELLCHECK_VERSION}:${PATH}"
  export PATH
fi

${CI_RETRY_EXE} pip3 install codespell==1.15.0
${CI_RETRY_EXE} pip3 install flake8==3.7.8
