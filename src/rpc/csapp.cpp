// Copyright (c) 2024 The CSCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// RPC commands for the CSApp subsystem:
//   listcsapps    — list all registered apps (optional status filter)
//   getcsapp      — get full spec of a single app by deployment_id
//   rebuildcsappdb — rescan chain and rebuild the in-memory app cache

#include "csapp/csapp.h"
#include "rpc/server.h"
#include "utilstrencodings.h"
#include "main.h"
#include "univalue/include/univalue.h"

static UniValue CSAppDataToUniValue(const CSAppData& d)
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("deployment_id",  d.deploymentId);
    obj.pushKV("owner",          d.owner);
    obj.pushKV("spec",           d.specJson);
    obj.pushKV("ip",             d.ip);
    obj.pushKV("registered_at",  (int)d.registeredAt);
    obj.pushKV("updated_at",     (int)d.updatedAt);
    obj.pushKV("locked_cscoin",  ValueFromAmount(d.lockedCscoin));

    std::string statusStr;
    switch (d.status) {
        case CSAPP_STATUS_RUNNING: statusStr = "RUNNING";  break;
        case CSAPP_STATUS_STOPPED: statusStr = "STOPPED";  break;
        case CSAPP_STATUS_EXPIRED: statusStr = "EXPIRED";  break;
        default:                   statusStr = "UNKNOWN";  break;
    }
    obj.pushKV("status",     statusStr);
    obj.pushKV("tx_hash",    d.txHash.GetHex());
    obj.pushKV("last_tx",    d.lastTxHash.GetHex());
    return obj;
}

UniValue listcsapps(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "listcsapps ( \"status\" )\n"
            "\nReturn a list of all registered CSApps.\n"
            "\nArguments:\n"
            "1. status  (string, optional) Filter: RUNNING | STOPPED | EXPIRED\n"
            "\nResult:\n"
            "[{ deployment_id, owner, spec, status, registered_at, ... }, ...]\n"
            "\nExamples:\n"
            + HelpExampleCli("listcsapps", "")
            + HelpExampleCli("listcsapps", "\"RUNNING\"")
            + HelpExampleRpc("listcsapps", "\"RUNNING\"")
        );

    int8_t statusFilter = -1;
    if (params.size() == 1) {
        std::string s = params[0].get_str();
        if      (s == "RUNNING") statusFilter = CSAPP_STATUS_RUNNING;
        else if (s == "STOPPED") statusFilter = CSAPP_STATUS_STOPPED;
        else if (s == "EXPIRED") statusFilter = CSAPP_STATUS_EXPIRED;
        else throw std::runtime_error("Invalid status. Use RUNNING, STOPPED or EXPIRED.");
    }

    UniValue arr(UniValue::VARR);
    for (const auto& d : g_csappCache.ListApps(statusFilter))
        arr.push_back(CSAppDataToUniValue(d));
    return arr;
}

UniValue getcsapp(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getcsapp \"deployment_id\"\n"
            "\nReturn full data of a single CSApp.\n"
            "\nArguments:\n"
            "1. deployment_id  (string, required) UUID of the deployment\n"
            "\nExamples:\n"
            + HelpExampleCli("getcsapp", "\"550e8400-e29b-41d4-a716-446655440000\"")
            + HelpExampleRpc("getcsapp", "\"550e8400-e29b-41d4-a716-446655440000\"")
        );

    std::string depId = params[0].get_str();
    CSAppData data;
    if (!g_csappCache.GetApp(depId, data))
        throw std::runtime_error("App not found: " + depId);
    return CSAppDataToUniValue(data);
}

UniValue rebuildcsappdb(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "rebuildcsappdb\n"
            "\nRescan the entire blockchain and rebuild the CSApp in-memory cache.\n"
            "This may take several minutes on a fully synced node.\n"
            "\nExamples:\n"
            + HelpExampleCli("rebuildcsappdb", "")
            + HelpExampleRpc("rebuildcsappdb", "")
        );

    RebuildCSAppCache();
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("rebuilt", true);
    ret.pushKV("apps",    (int)g_csappCache.Size());
    return ret;
}

static const CRPCCommand commands[] =
{   //  category    name                actor                okSafeMode
    { "csapp",  "listcsapps",       &listcsapps,        false },
    { "csapp",  "getcsapp",         &getcsapp,          false },
    { "hidden", "rebuildcsappdb",   &rebuildcsappdb,    false },
};

void RegisterCSAppRPCCommands(CRPCTable& tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
