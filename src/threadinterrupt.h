// Copyright (c) 2016-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_THREADINTERRUPT_H
#define BITCOIN_THREADINTERRUPT_H

#include <sync.h>
#include <threadsafety.h>

#include <atomic>
#include <chrono>
#include <condition_variable>

/*
    A helper class for interruptible sleeps. Calling operator() will interrupt
    any current sleep, and after that point operator bool() will return true
    until reset.
*/
class CThreadInterrupt
{
public:
    CThreadInterrupt();
    explicit operator bool() const;
    void operator()() REQUIRES(!mut);
    void reset();
    bool sleep_for(std::chrono::milliseconds rel_time) REQUIRES(!mut);
    bool sleep_for(std::chrono::seconds rel_time) REQUIRES(!mut);
    bool sleep_for(std::chrono::minutes rel_time) REQUIRES(!mut);

private:
    std::condition_variable cond;
    Mutex mut;
    std::atomic<bool> flag;
};

#endif //BITCOIN_THREADINTERRUPT_H
