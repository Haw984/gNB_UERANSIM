//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "udp_task.hpp"
#include <cstdint>
#include <cstring>
#include <set>
#include <cstdlib>
#include <cmath>
#include <ue/app/task.hpp>
#include <ue/nts.hpp>
#include <utils/common.hpp>
#include <utils/constants.hpp>
#include <numeric>
#include <arpa/inet.h>
#include <cstring>
#include <stdexcept> // For std::runtime_error

static constexpr const int BUFFER_SIZE = 16384;
static constexpr const int LOOP_PERIOD = 1000;
static constexpr const int RECEIVE_TIMEOUT = 200;
static constexpr const int HEARTBEAT_THRESHOLD = 10000; // (LOOP_PERIOD + RECEIVE_TIMEOUT)'dan büyük olmalı

bool NtsTask::connectionEstablished = false;
bool NtsTask::establishConnection = false;
std::string NtsTask::state = "";
int NtsTask::counter = 0;
// Static member of wifiAp struct
NtsTask::wifiAp NtsTask::apSelection= {{},{},{}};


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

// Function to add or update IP address, dBm, and additional info in a wifiAp struct
void addOrUpdateIPAddress(const std::string& ipv4Address, int newDbm, const std::string& additionalInfo) {
    // Check if the IPv4 address already exists in the vector
    auto it = std::find(NtsTask::apSelection.ipv4address.begin(), NtsTask::apSelection.ipv4address.end(), ipv4Address);

    if (it != NtsTask::apSelection.ipv4address.end()) {
        // If address exists, find its index
        size_t index = std::distance(NtsTask::apSelection.ipv4address.begin(), it);
        // Update dBm and additional info at the found index
        NtsTask::apSelection.dbmWifi[index] = newDbm;
        NtsTask::apSelection.additionalInfo[index] = additionalInfo;
    } else {
        // If address doesn't exist, add it to the vectors
        NtsTask::apSelection.ipv4address.push_back(ipv4Address);
        NtsTask::apSelection.dbmWifi.push_back(newDbm);
        NtsTask::apSelection.additionalInfo.push_back(additionalInfo);
    }
}

 // Function to sort IP addresses based on dBm values and additional info
void sortByDBM() {
        std::vector<size_t> indices(NtsTask::apSelection.ipv4address.size());
        std::iota(indices.begin(), indices.end(), 0); // Initialize indices to 0, 1, 2, ..., n-1

        // Custom sorting function based on dBm values and additional info
        std::sort(indices.begin(), indices.end(),
                  [](size_t a, size_t b) {
                      // First, compare dBm values
                      if (NtsTask::apSelection.dbmWifi[a] != NtsTask::apSelection.dbmWifi[b]) {
                          return NtsTask::apSelection.dbmWifi[a] > NtsTask::apSelection.dbmWifi[b];
                      }
                      // If dBm values are the same, compare additional info
                      // If additional info is "Establish", it should come first
                      if (NtsTask::apSelection.additionalInfo[a] == "Maintain" && NtsTask::apSelection.additionalInfo[b] != "Maintain") {
                          return true;
                      }
                      return false; // If additional info is not "Establish" or both are "Establish", maintain order
                  });

        // Rearrange IP addresses, dBm values, and additional info based on sorted indices
        std::vector<std::string> sortedIPv4;
        std::vector<int> sortedDBM;
        std::vector<std::string> sortedAdditionalInfo;

        for (size_t i = 0; i < indices.size(); ++i) {
            sortedIPv4.push_back(NtsTask::apSelection.ipv4address[indices[i]]);
            sortedDBM.push_back(NtsTask::apSelection.dbmWifi[indices[i]]);
            sortedAdditionalInfo.push_back(NtsTask::apSelection.additionalInfo[indices[i]]);
        }

        // Update apSelection with sorted data
        NtsTask::apSelection.ipv4address = sortedIPv4;
        NtsTask::apSelection.dbmWifi = sortedDBM;
        NtsTask::apSelection.additionalInfo = sortedAdditionalInfo;
    }

int findMaintainIndex(const std::string& ipv4Address) {
    auto it = std::find(NtsTask::apSelection.ipv4address.begin(), NtsTask::apSelection.ipv4address.end(), ipv4Address);
    if (it != NtsTask::apSelection.ipv4address.end()) {
        size_t index = std::distance(NtsTask::apSelection.ipv4address.begin(), it);
        if (index < NtsTask::apSelection.additionalInfo.size() && NtsTask::apSelection.additionalInfo[index] == "Maintain") {
            return index;
        }
    }
    return -1; // "Maintain" not found for the given IPv4 address
}


namespace nr::ue
{

RlsUdpTask::RlsUdpTask(TaskBase *base, RlsSharedContext *shCtx, const std::vector<std::string> &searchSpace, std::vector<Vector3> simPos, const std::string mobPattern,const float velocity, const bool wifi)
    : m_server{}, m_ctlTask{}, m_shCtx{shCtx}, m_searchSpace{}, m_cells{}, m_cellIdToSti{}, m_lastLoop{},m_simPos{simPos},
      m_mobPattern{mobPattern}, m_cellIdCounter{}, m_velocity{velocity}, m_wifi{wifi}
{
    m_logger = base->logBase->makeUniqueLogger(base->config->getLoggerPrefix() + "rls-udp");

    m_server = new udp::UdpServer();
    for (auto &ip : searchSpace)
        m_searchSpace.emplace_back(ip, cons::RadioLinkPort);
}

void RlsUdpTask::onStart()
{
   m_simPosIndex = 0;
   speedTimeCalculation(m_simPos, m_velocity);
}

void RlsUdpTask::onLoop()
{
    auto current = utils::CurrentTimeMillis();
    if (current - m_lastLoop > LOOP_PERIOD)
    {
        if(m_mobPattern == "linear")
        {
            m_lastLoop = current;
            // Pass the corresponding Vector3 to heartbeatCycle
            int lastIndex = m_simPos.size() - 1;
            if (m_simPosIndex == lastIndex)
            {
                heartbeatCycle(current, m_simPos[lastIndex]);
                m_simPosIndex = lastIndex;
            }
            else
            {
                heartbeatCycle(current, m_simPos[m_simPosIndex]);
                m_simPosIndex++;
            }
        }
        else
        {
            m_lastLoop = current;
            // Increment the index to move to the next position in m_simPos and start again 
            m_simPosIndex = (m_simPosIndex + 1) % m_simPos.size();
            heartbeatCycle(current, m_simPos[m_simPosIndex]);
        }
        //heartbeatCycle(current, m_simPos);
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
    else
    {
	NtsTask::counter++;
    }
}

void RlsUdpTask::onQuit()
{
    delete m_server;
}

void RlsUdpTask::sendRlsPdu(const InetAddress &addr, const rls::RlsMessage &msg)
{
    OctetString stream;
    rls::EncodeRlsMessage(msg, stream);

    m_server->Send(addr, stream.data(), static_cast<size_t>(stream.length()));
}

void RlsUdpTask::send(int cellId, const rls::RlsMessage &msg)
{
    if (m_cellIdToSti.count(cellId))
    {
        auto sti = m_cellIdToSti[cellId];
        sendRlsPdu(m_cells[sti].address, msg);
    }
}

void RlsUdpTask::receiveRlsPdu(const InetAddress &addr, std::unique_ptr<rls::RlsMessage> &&msg)
{
    if (msg->msgType == rls::EMessageType::HEARTBEAT_ACK)
    {
        if (!m_cells.count(msg->sti))
        {
            m_cells[msg->sti].cellId = ++m_cellIdCounter;
            m_cellIdToSti[m_cells[msg->sti].cellId] = msg->sti;
        }

        int oldDbm = INT32_MIN;
        if (m_cells.count(msg->sti))
            oldDbm = m_cells[msg->sti].dbm;

        m_cells[msg->sti].address = addr;
        m_cells[msg->sti].lastSeen = utils::CurrentTimeMillis();

        int newDbm = ((const rls::RlsHeartBeatAck &)*msg).dbm;
        m_cells[msg->sti].dbm = newDbm;
        if (m_wifi)
        {
            std::string ipv4Address = getIPv4AddressString(addr);
            if (newDbm > -120)
            {
            int index = findMaintainIndex(ipv4Address);
            if(index != -1){
                addOrUpdateIPAddress(ipv4Address, newDbm, "Maintain");}
            else {
                addOrUpdateIPAddress(ipv4Address, newDbm, "Establish");}
            NtsTask::establishConnection = true;
            sortByDBM();
            }
            else if (newDbm < -120)
            {
            addOrUpdateIPAddress(ipv4Address, newDbm, "");
            sortByDBM();
            }
        }
	    NtsTask::counter = 0;
        if (oldDbm != newDbm)
           {onSignalChangeOrLost(m_cells[msg->sti].cellId);}
	    return;
    }

    if (!m_cells.count(msg->sti))
    {
        // if no HB-ACK received yet, and the message is not HB-ACK, then ignore the message
        state = std::move("Release");
        NtsTask::connectionEstablished = false;
        return;
    }

    auto w = std::make_unique<NmUeRlsToRls>(NmUeRlsToRls::RECEIVE_RLS_MESSAGE);
    if (msg->msgType == rls::EMessageType::SESSION_TRANSMISSION)
    {
        w->old_cellId = m_cells[msg->sti].cellId;
        w->cellId = findCellWithHighestDbm(m_cells);//cell id var is use to send packet to max dbm cell
    }
    else{
        w->cellId = m_cells[msg->sti].cellId;
    }
    
    w->msg = std::move(msg);
    m_ctlTask->push(std::move(w));
}

void RlsUdpTask::onSignalChangeOrLost(int cellId)
{
    int dbm = INT32_MIN;
    if (m_cellIdToSti.count(cellId))
    {
        auto sti = m_cellIdToSti[cellId];
        dbm = m_cells[sti].dbm;
    }

    auto w = std::make_unique<NmUeRlsToRls>(NmUeRlsToRls::SIGNAL_CHANGED);
    w->cellId = cellId;
    w->dbm = dbm;
    m_ctlTask->push(std::move(w));

}

void RlsUdpTask::heartbeatCycle(uint64_t time, const Vector3 &simPos)
{
    std::set<std::pair<uint64_t, int>> toRemove;

    for (auto &cell : m_cells)
    {
        auto delta = time - cell.second.lastSeen;
	    //long unsigned int total_timeout = RECEIVE_TIMEOUT +  velocity_in_time;
        if (delta >  HEARTBEAT_THRESHOLD)
            toRemove.insert({cell.first, cell.second.cellId});
    }

    for (auto cell : toRemove)
    {
        m_cells.erase(cell.first);
        m_cellIdToSti.erase(cell.second);
    }

    for (auto cell : toRemove)
       { onSignalChangeOrLost(cell.second);}

    for (auto &addr : m_searchSpace)
    {
        rls::RlsHeartBeat msg{m_shCtx->sti};
        msg.simPos = simPos;
        sendRlsPdu(addr, msg);
    }
}

void RlsUdpTask::initialize(NtsTask *ctlTask)
{
    m_ctlTask = ctlTask;
}

void RlsUdpTask::speedTimeCalculation(std::vector<Vector3>& simPos, float velocity)
{
    if (simPos.size() < 2 || velocity <= 0.0f) {
        return; // No movement or invalid velocity
    }

    std::vector<Vector3> modifiedSimPos;

    // Loop through each consecutive pair of points
    for (size_t i = 1; i < simPos.size(); ++i) {
        float deltaX = simPos[i].x - simPos[i - 1].x;
        float deltaY = simPos[i].y - simPos[i - 1].y;
        float deltaZ = simPos[i].z - simPos[i - 1].z;

        // Calculate the distance between the two points
        float squaredDistance = deltaX * deltaX + deltaY * deltaY + deltaZ * deltaZ;
        float distance = std::sqrt(squaredDistance);

        // Calculate the time (in seconds) to travel between these two points
        float time_in_sec = distance / velocity;

        // Calculate how many times the UE should "stay" at the first point
        int repetitions = static_cast<int>(std::round(time_in_sec));

        // Repeat the current position for the calculated duration
        for (int j = 0; j < repetitions; ++j) {
            modifiedSimPos.push_back(simPos[i - 1]); // Repeat the starting point of the segment
        }
    }

    // For the final point, append it without repetition
    modifiedSimPos.push_back(simPos.back());

    // Replace the original simPos with the modified one
    simPos = std::move(modifiedSimPos);
}

// Function to find the cell with the highest dBm
int RlsUdpTask::findCellWithHighestDbm(const std::unordered_map<uint64_t, CellInfo>& m_cells) {
    int maxDbm = std::numeric_limits<int>::min();  // Initialize to the lowest possible dBm value
    int cellWithMaxDbm = -1;  // Initialize cell ID

    // Iterate over the map to find the cell with the highest dBm
    for (const auto& [key, cellInfo] : m_cells) {
        if (cellInfo.dbm > maxDbm) {
            maxDbm = cellInfo.dbm;
            cellWithMaxDbm = cellInfo.cellId;
        }
    }

    return cellWithMaxDbm;  // Return the cell ID with the highest dBm
}

} // namespace nr::ue
