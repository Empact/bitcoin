// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WARNINGS_H
#define BITCOIN_WARNINGS_H

#include <stdlib.h>
#include <string>

void SetMiscWarning(const std::string& strWarning);
void SetfLargeWorkForkFound(bool flag);
bool GetfLargeWorkForkFound();
void SetfLargeWorkInvalidChainFound(bool flag);

enum class WarningContext {
    GUI,
    STATUS_BAR
}

/** Format a string that describes several potential problems detected by the core.
 * @param[in] context can have the following values:
 * - STATUS_BAR: get the highest priority warning
 * - GUI: get all warnings, translated (where possible) for GUI
 * This function only returns the highest priority warning of the set selected by strFor.
 */
std::string GetWarnings(const WarningContext context);

#endif //  BITCOIN_WARNINGS_H
