//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include <memory>
#include <thread>
#include <ue/nts.hpp>
#include <ue/tun/task.hpp>
#include <ue/types.hpp>
#include <unordered_map>
#include <utils/logger.hpp>
#include <utils/nts.hpp>
#include <vector>

namespace nr::ue
{

class UeAppTask : public NtsTask
{
  private:
    TaskBase *m_base;
    std::unique_ptr<Logger> m_logger;
    std::array<TunTask *, 16> m_tunTasks{};
    ECmState m_cmState{};
    std::string m_tunName;
    std::unique_ptr<PduSession> m_pduSession;

    friend class UeCmdHandler;

  public:
    std::vector<unsigned char> bytes;
    explicit UeAppTask(TaskBase *base);
    ~UeAppTask() override = default;

  protected:
    void onStart() override;
    void onLoop() override;
    void onQuit() override;

  private:
    void receiveStatusUpdate(NmUeStatusUpdate &msg);
    void setupTunInterface(const PduSession *pduSession);
    //void releaseSession(std::unique_ptr<nr::ue::PduSession>  *pduSession);
    void updateRoutingForTunInterface();
    bool CheckInterfaceAndFetchIp(const std::string &prefix, std::string &interfaceName, std::string &ipAddress);


};

} // namespace nr::ue
