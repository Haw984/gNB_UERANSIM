//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "rls_pdu.hpp"

#include <utils/constants.hpp>
#include "asn/ngap/ASN_NGAP_QosFlowSetupRequestItem.h"

namespace rls
{

void EncodeRlsMessage(const RlsMessage &msg, OctetString &stream)
{
    stream.appendOctet(0x03); // (Just for old RLS compatibility)

    stream.appendOctet(cons::Major);
    stream.appendOctet(cons::Minor);
    stream.appendOctet(cons::Patch);
    stream.appendOctet(static_cast<uint8_t>(msg.msgType));
    stream.appendOctet8(msg.sti);
    if (msg.msgType == EMessageType::HEARTBEAT)
    {
        auto &m = (const RlsHeartBeat &)msg;
        stream.appendOctet4(m.simPos.x);
        stream.appendOctet4(m.simPos.y);
        stream.appendOctet4(m.simPos.z);
    }
    else if (msg.msgType == EMessageType::HEARTBEAT_ACK)
    {
        auto &m = (const RlsHeartBeatAck &)msg;
        stream.appendOctet4(m.dbm);
    }
    else if (msg.msgType == EMessageType::PDU_TRANSMISSION)
    {
        auto &m = (const RlsPduTransmission &)msg;
        stream.appendOctet(static_cast<uint8_t>(m.pduType));
        stream.appendOctet4(m.pduId);
        stream.appendOctet4(m.payload);
        stream.appendOctet4(m.pdu.length());
        stream.append(m.pdu);
    }
    else if (msg.msgType == EMessageType::PDU_TRANSMISSION_ACK)
    {
        auto &m = (const RlsPduTransmissionAck &)msg;
        stream.appendOctet4(static_cast<uint32_t>(m.pduIds.size()));
        for (auto pduId : m.pduIds)
            stream.appendOctet4(pduId);
    }
    //Urwah
    else if (msg.msgType == EMessageType::RELEASE_SESSION)
    {
        auto &m = (const RlsTerminateSession &)msg;
        stream.appendOctet4(m.pduId);
        stream.appendOctet4(m.psi);

    }
    else if (msg.msgType == EMessageType::SESSION_TRANSMISSION)
    {
        auto &m = (const RlsSessionTransmission &)msg;
        stream.appendOctet4(m.pduId);
        stream.appendOctet4(m.payload);
        stream.appendOctet4(m.amfId);
        auto &qosList = m.m_pduSession->qosFlows->list;
        stream.appendOctet4(static_cast<uint32_t>(m.m_pduSession->ueId)); // Serialize ueId
        stream.appendOctet4(static_cast<uint32_t>(m.m_pduSession->psi));  // Serialize psi

        // Serialize AggregateMaximumBitRate
        stream.appendOctet8(m.m_pduSession->sessionAmbr.dlAmbr); // Serialize dlAmbr
        stream.appendOctet8(m.m_pduSession->sessionAmbr.ulAmbr); // Serialize ulAmbr

        // Serialize boolean as a single byte
        stream.appendOctet(static_cast<uint8_t>(m.m_pduSession->dataForwardingNotPossible));

        // Serialize PduSessionType as a single byte
        stream.appendOctet(static_cast<uint8_t>(m.m_pduSession->sessionType));

        // Serialize GtpTunnel upTunnel
        stream.appendOctet4(m.m_pduSession->upTunnel.teid); // Serialize TEID
        stream.appendOctet4(m.m_pduSession->upTunnel.address.length());
        stream.append(m.m_pduSession->upTunnel.address);    // Serialize address

        // Serialize GtpTunnel downTunnel
        stream.appendOctet4(m.m_pduSession->downTunnel.teid); // Serialize TEID
        stream.appendOctet4(m.m_pduSession->downTunnel.address.length());    // Serialize address
        stream.append(m.m_pduSession->downTunnel.address);    // Serialize address
        stream.appendOctet4(static_cast<int>(qosList.count)); // Serialize the number of QoS Flows
        for (int iQos = 0; iQos < static_cast<int>(qosList.count); iQos++) {
            stream.appendOctet4(static_cast<int>(qosList.array[iQos]->qosFlowIdentifier)); // Serialize QoS Flow Identifier
        }
        // Encode the UE Security Capability into the stream
        nas::IEUeSecurityCapability::Encode(m.m_ueSecurityCapability, stream);

    }   
}

std::unique_ptr<RlsMessage> DecodeRlsMessage(const OctetView &stream)
{
    auto first = stream.readI(); // (Just for old RLS compatibility)
    if (first != 3)
        return nullptr;

    if (stream.read() != cons::Major)
        return nullptr;
    if (stream.read() != cons::Minor)
        return nullptr;
    if (stream.read() != cons::Patch)
        return nullptr;

    auto msgType = static_cast<EMessageType>(stream.readI());
    uint64_t sti = stream.read8UL();

    if (msgType == EMessageType::HEARTBEAT)
    {
        auto res = std::make_unique<RlsHeartBeat>(sti);
        res->simPos.x = stream.read4I();
        res->simPos.y = stream.read4I();
        res->simPos.z = stream.read4I();
        return res;
    }
    else if (msgType == EMessageType::HEARTBEAT_ACK)
    {
        auto res = std::make_unique<RlsHeartBeatAck>(sti);
        res->dbm = stream.read4I();
        return res;
    }
    else if (msgType == EMessageType::PDU_TRANSMISSION)
    {
        auto res = std::make_unique<RlsPduTransmission>(sti);
        res->pduType = static_cast<EPduType>((uint8_t)stream.read());
        res->pduId = stream.read4UI();
        res->payload = stream.read4UI();
        res->pdu = stream.readOctetString(stream.read4I());
        return res;
    }
    else if (msgType == EMessageType::PDU_TRANSMISSION_ACK)
    {
        auto res = std::make_unique<RlsPduTransmissionAck>(sti);
        auto count = stream.read4UI();
        res->pduIds.reserve(count);
        for (uint32_t i = 0; i < count; i++)
            res->pduIds.push_back(stream.read4UI());
        return res;
    }
    else if (msgType == EMessageType::SESSION_TRANSMISSION)
    {
        auto res = std::make_unique<RlsSessionTransmission>(sti);
        res->pduId = stream.read4UI();
        res->payload = stream.read4UI();
        res->amfId = stream.read4UI();

        int ueId = stream.read4UI();
        int psi = stream.read4UI();

        res->m_pduSession = std::make_unique<nr::ue::PduSessionResource>(ueId, psi);

        // Read AggregateMaximumBitRate
        res->m_pduSession->sessionAmbr.dlAmbr = stream.read8UL();
        res->m_pduSession->sessionAmbr.ulAmbr = stream.read8UL();

        // Read boolean and PduSessionType
        res->m_pduSession->dataForwardingNotPossible = static_cast<bool>(stream.readI());
        res->m_pduSession->sessionType = static_cast<PduSessionType>(stream.readI());

        // Read GtpTunnel upTunnel
        res->m_pduSession->upTunnel.teid = stream.read4UI();
        res->m_pduSession->upTunnel.address = stream.readOctetString(stream.read4I());

        // Read GtpTunnel downTunnel
        res->m_pduSession->downTunnel.teid = stream.read4UI();
        res->m_pduSession->downTunnel.address = stream.readOctetString(stream.read4I());

        // Read QoS Flows
        int qosFlowCount = stream.read4I();

        // Allocate space for qosFlows
        asn::Unique<ASN_NGAP_QosFlowSetupRequestList> newQosFlows(asn::New<ASN_NGAP_QosFlowSetupRequestList>());
        res->m_pduSession->qosFlows = std::move(newQosFlows);
        res->m_pduSession->qosFlows->list.array = new ASN_NGAP_QosFlowSetupRequestItem*[qosFlowCount];

        for (int iQos = 0; iQos < qosFlowCount; iQos++) {
            res->m_pduSession->qosFlows->list.array[iQos] = new ASN_NGAP_QosFlowSetupRequestItem();
            res->m_pduSession->qosFlows->list.array[iQos]->qosFlowIdentifier = stream.read4I();
        }
        res->m_pduSession->qosFlows->list.count = qosFlowCount;

        return res;

    }
    else if (msgType == EMessageType::XN_SESSION_TRANSMISSION)
    {
        auto res = std::make_unique<RlsXnSessionTransmission>(sti);

        res->pduId = stream.read4UI();
        res->payload = stream.read4UI();

        return res;

    }

    return nullptr;
}

} // namespace rls
