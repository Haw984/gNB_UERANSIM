//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include <cstdint>
#include <memory>
#include <gnb/types.hpp>

#include <utils/common_types.hpp>
#include <utils/octet_string.hpp>
#include <utils/octet_view.hpp>
#include <lib/nas/msg.hpp>

namespace rls
{

enum class EMessageType : uint8_t
{
    RESERVED = 0,

    DEPRECATED1 = 1,
    DEPRECATED2 = 2,
    DEPRECATED3 = 3,

    HEARTBEAT = 4,
    HEARTBEAT_ACK = 5,
    PDU_TRANSMISSION = 6,
    PDU_TRANSMISSION_ACK = 7,
    //Urwah
    SESSION_TRANSMISSION = 8,
    XN_SESSION_TRANSMISSION = 9,

};

enum class EPduType : uint8_t
{
    RESERVED = 0,
    RRC,
    DATA
};

struct RlsMessage
{
    const EMessageType msgType;
    const uint64_t sti{};

    explicit RlsMessage(EMessageType msgType, uint64_t sti) : msgType(msgType), sti(sti)
    {
    }
};

struct RlsHeartBeat : RlsMessage
{
    Vector3 simPos;

    explicit RlsHeartBeat(uint64_t sti) : RlsMessage(EMessageType::HEARTBEAT, sti)
    {
    }
};

struct RlsHeartBeatAck : RlsMessage
{
    int dbm{};

    explicit RlsHeartBeatAck(uint64_t sti) : RlsMessage(EMessageType::HEARTBEAT_ACK, sti)
    {
    }
};

//Urwah
struct RlsSessionTransmission : RlsMessage
{
    EPduType pduType{};
    uint32_t pduId{};
    uint32_t payload{};
    uint32_t amfId{};

    std::unique_ptr<nr::gnb::PduSessionResource> m_pduSession;
    nas::IEUeSecurityCapability m_ueSecurityCapability;


    explicit RlsSessionTransmission(uint64_t sti) : RlsMessage(EMessageType::SESSION_TRANSMISSION, sti)
    {
    }
};

struct RlsXnSessionTransmission : RlsMessage
{
    EPduType pduType{};
    uint32_t pduId{};
    uint32_t payload{};
    uint32_t amfId{};

    std::unique_ptr<nr::gnb::PduSessionResource> m_pduSession;


    explicit RlsXnSessionTransmission(uint64_t sti) : RlsMessage(EMessageType::XN_SESSION_TRANSMISSION, sti)
    {
    }
};

struct RlsPduTransmission : RlsMessage
{
    EPduType pduType{};
    uint32_t pduId{};
    uint32_t payload{};
    OctetString pdu{};

    explicit RlsPduTransmission(uint64_t sti) : RlsMessage(EMessageType::PDU_TRANSMISSION, sti)
    {
    }
};

struct RlsPduTransmissionAck : RlsMessage
{
    std::vector<uint32_t> pduIds;

    explicit RlsPduTransmissionAck(uint64_t sti) : RlsMessage(EMessageType::PDU_TRANSMISSION_ACK, sti)
    {
    }
};

void EncodeRlsMessage(const RlsMessage &msg, OctetString &stream);
std::unique_ptr<RlsMessage> DecodeRlsMessage(const OctetView &stream);

} // namespace rls