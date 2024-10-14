//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "udp_task.hpp"

#include <cmath>
#include <cstdint>
#include <cstring>
#include <set>
#include <unistd.h>

#include <gnb/nts.hpp>
#include <utils/common.hpp>
#include <utils/constants.hpp>
#include <utils/libc_error.hpp>
#include <string>
#include <iostream>
static constexpr const int BUFFER_SIZE = 16384;

static constexpr const int LOOP_PERIOD = 1000;
static constexpr const int RECEIVE_TIMEOUT = 200;
static constexpr const int HEARTBEAT_THRESHOLD = 5000; // (LOOP_PERIOD + RECEIVE_TIMEOUT)'dan büyük olmalı

static constexpr const int MIN_ALLOWED_DBM = -120;
bool NtsTask::flag = false;

#include <arpa/inet.h>
#include <cstring>
#include <stdexcept> // For std::runtime_error

std::string getIPv4AddressString(const InetAddress &inetAddress) {
  if (inetAddress.getIpVersion() != 4) {
    return ""; // Not an IPv4 address
  }

  // Check if getSockAddr returns a null pointer (potential error)
  const sockaddr *addr = inetAddress.getSockAddr();
  if (addr == nullptr) {
    throw std::runtime_error("InetAddress object does not contain a valid address");
  }

  // Cast to const sockaddr_in* only if the IP version is 4
  const sockaddr_in *sin = reinterpret_cast<const sockaddr_in *>(addr);

  char ipString[INET_ADDRSTRLEN]; // Buffer to store string address
  if (inet_ntop(AF_INET, &(sin->sin_addr), ipString, INET_ADDRSTRLEN) == nullptr) {
    // Handle inet_ntop error (unlikely, but possible)
    throw std::runtime_error("Error converting address to string");
  }

  return std::string(ipString);
}



static int EstimateSimulatedDbm(const Vector3 &myPos, const Vector3 &uePos)
{
    int deltaX = myPos.x - uePos.x;
    int deltaY = myPos.y - uePos.y;
    int deltaZ = myPos.z - uePos.z;

    int distance = static_cast<int>(std::sqrt(deltaX * deltaX + deltaY * deltaY + deltaZ * deltaZ));
    if (distance == 0)
        return -1; // 0 may be confusing for people
    return -distance;
}

#include <string>
#include <cstdlib>

// Function to execute a command
int execute_command(const std::string& command) {
    std::cout<<command<<std::endl;
    return system(command.c_str());
}

// Function to build the command
std::string build_command(const std::string& base_cmd, const std::string& mid_cmd,  const std::string& target_network, const std::string& end_cmd) {
    return base_cmd + mid_cmd + target_network + end_cmd;
}

// Function to add or delete route
int route(const std::string& cmd_start, const std::string& cmd_mid, const std::string& target_network, const std::string& end_cmd) {
    std::string cmd = build_command(cmd_start, cmd_mid, target_network, end_cmd);
    return execute_command(cmd);
}


namespace nr::gnb
{

RlsUdpTask::RlsUdpTask(TaskBase *base, uint64_t sti, Vector3 phyLocation, bool wifi, std::string ueInterface, std::string interface)
    : m_server{}, m_ctlTask{}, m_sti{sti}, m_phyLocation{phyLocation}, m_lastLoop{}, m_stiToUe{}, m_ueMap{}, m_newIdCounter{}
    , m_wifi{wifi}, m_ueInterface{ueInterface},m_interface{interface}
{
    m_logger = base->logBase->makeUniqueLogger("rls-udp");

    try
    {
        m_server = new udp::UdpServer(base->config->linkIp, cons::RadioLinkPort);
    }
    catch (const LibError &e)
    {
        m_logger->err("RLS failure [%s]", e.what());
        quit();
        return;
    }
}

void RlsUdpTask::onStart()
{
}

void RlsUdpTask::onLoop()
{
    auto current = utils::CurrentTimeMillis();
    if (current - m_lastLoop > LOOP_PERIOD)
    {
        m_lastLoop = current;
        heartbeatCycle(current);
    }

    uint8_t buffer[BUFFER_SIZE];
    InetAddress peerAddress;
    int size = m_server->Receive(buffer, BUFFER_SIZE, RECEIVE_TIMEOUT, peerAddress);
    if (size > 0)
    {
        auto rlsMsg = rls::DecodeRlsMessage(OctetView{buffer, static_cast<size_t>(size)});
        if (rlsMsg == nullptr)
            m_logger->err("Unable to decode RLS message");
        else
            receiveRlsPdu(peerAddress, std::move(rlsMsg));
    }
}

void RlsUdpTask::onQuit()
{
    delete m_server;
}

void RlsUdpTask::receiveRlsPdu(const InetAddress &addr, std::unique_ptr<rls::RlsMessage> &&msg)
{
    if (msg->msgType == rls::EMessageType::HEARTBEAT)
    {
        int dbm = EstimateSimulatedDbm(m_phyLocation, ((const rls::RlsHeartBeat &)*msg).simPos);
	    std::string ipv4Address = getIPv4AddressString(addr);
        if (dbm < MIN_ALLOWED_DBM)
        {
	    if(m_wifi == true)
	    {
            if (NtsTask::flag == true)
            {
                int status = route("iptables -D FORWARD ","-i "+ m_interface + " -o "+ m_ueInterface+ " -s ", ipv4Address," -j ACCEPT");
                status = route("iptables -D FORWARD ","-i "+ m_ueInterface + " -o "+ m_interface+ " -s ", ipv4Address, " -j ACCEPT");
                status = route("iptables -A FORWARD ","-i "+ m_interface + " -o "+ m_ueInterface+ " -s ", ipv4Address, " -j DROP");
                status = route("iptables -A FORWARD ","-i "+ m_ueInterface + " -o "+ m_interface+ " -s ", ipv4Address, " -j DROP");
            if (status == 0){
                m_logger->info("Weak signal power.");
                m_logger->info("Wifi connection removed.");}
            }
            NtsTask::flag = false;
	    }
            return;
        }

        else if (dbm > MIN_ALLOWED_DBM && m_wifi == true)
        {
            if(m_wifi == true)
            {
                if (NtsTask::flag == false)
                {
                    if(m_interface == "" || m_ueInterface == "")
                    {
                        m_logger->err("Interface not provided.");
                        return;
                    }
                    else
                    {
                        m_logger->info("Wifi request received.");
                        int status = system(" iptables -F");
                        status = route("iptables -A FORWARD ","-i "+ m_interface + " -o "+ m_ueInterface + " -s ", ipv4Address, " -j ACCEPT");
                        status = route("iptables -A FORWARD ","-i "+ m_ueInterface + " -o "+ m_interface + " -s ", ipv4Address, " -j ACCEPT");
                        if (status == 0)
                        {
                            m_logger->info("Wifi connection successfully established.");
                        }
                        NtsTask::flag = true;
                    }
                }
            }
        }
        if (m_stiToUe.count(msg->sti))
        {
            int ueId = m_stiToUe[msg->sti];
            m_ueMap[ueId].address = addr;
            m_ueMap[ueId].lastSeen = utils::CurrentTimeMillis();
        }
        else
        {
            int ueId = ++m_newIdCounter;

            m_stiToUe[msg->sti] = ueId;
            m_ueMap[ueId].address = addr;
            m_ueMap[ueId].lastSeen = utils::CurrentTimeMillis();

            auto w = std::make_unique<NmGnbRlsToRls>(NmGnbRlsToRls::SIGNAL_DETECTED);
            w->ueId = ueId;
            m_ctlTask->push(std::move(w));
        }

        rls::RlsHeartBeatAck ack{m_sti};
        ack.dbm = dbm;

        sendRlsPdu(addr, ack);
        return;
    }

    if (!m_stiToUe.count(msg->sti))
    {
        // if no HB received yet, and the message is not HB, then ignore the message
        return;
    }

    auto w = std::make_unique<NmGnbRlsToRls>(NmGnbRlsToRls::RECEIVE_RLS_MESSAGE);
    w->ueId = m_stiToUe[msg->sti];
    w->msg = std::move(msg);
    m_ctlTask->push(std::move(w));
}

void RlsUdpTask::sendRlsPdu(const InetAddress &addr, const rls::RlsMessage &msg)
{
    OctetString stream;
    rls::EncodeRlsMessage(msg, stream);

    m_server->Send(addr, stream.data(), static_cast<size_t>(stream.length()));
}

void RlsUdpTask::heartbeatCycle(int64_t time)
{
    std::set<int> lostUeId{};
    std::set<uint64_t> lostSti{};

    for (auto &item : m_ueMap)
    {
        if (time - item.second.lastSeen > HEARTBEAT_THRESHOLD)
        {
            lostUeId.insert(item.first);
            lostSti.insert(item.second.sti);
        }
    }

    for (uint64_t sti : lostSti)
        m_stiToUe.erase(sti);

    for (int ueId : lostUeId)
        m_ueMap.erase(ueId);

    for (int ueId : lostUeId)
    {
        auto w = std::make_unique<NmGnbRlsToRls>(NmGnbRlsToRls::SIGNAL_LOST);
        w->ueId = ueId;
        m_ctlTask->push(std::move(w));
    }
}

void RlsUdpTask::initialize(NtsTask *ctlTask)
{
    m_ctlTask = ctlTask;
}

void RlsUdpTask::send(int ueId, const rls::RlsMessage &msg)
{
    if (ueId == 0)
    {
        for (auto &ue : m_ueMap)
            send(ue.first, msg);
        return;
    }

    if (!m_ueMap.count(ueId))
    {
        // ignore the message
        std::cout<<" Msg is ignored!!!"<<std::endl;
        return;
    }

    sendRlsPdu(m_ueMap[ueId].address, msg);
}

} // namespace nr::gnb
