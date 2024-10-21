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

#include <iostream>

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
    else if (msg.msgType == EMessageType::XN_SESSION_TRANSMISSION)
    {
        std::cout<<"msg.msgType == EMessageType::XN_SESSION_TRANSMISSION"<<std::endl;
        auto &m = (const RlsXnSessionTransmission &)msg;
        stream.appendOctet4(m.pduId);
        stream.appendOctet4(m.payload);
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


        res->m_pduSession = std::make_unique<nr::gnb::PduSessionResource>(ueId, psi);
        // Read AggregateMaximumBitRate
        res->m_pduSession->sessionAmbr.dlAmbr = stream.read8UL();
        res->m_pduSession->sessionAmbr.ulAmbr = stream.read8UL();

        // Read boolean and PduSessionType
        res->m_pduSession->dataForwardingNotPossible = static_cast<bool>(stream.readI());
        res->m_pduSession->sessionType = static_cast<PduSessionType>(stream.readI());

        // Read GtpTunnel upTunnel
        res->m_pduSession->upTunnel.teid = stream.read4UI();
        std::cout<<"res->m_pduSession->upTunnel.teid: "<<res->m_pduSession->upTunnel.teid<<std::endl;
        res->m_pduSession->upTunnel.address = stream.readOctetString(stream.read4I());
        std::cout << "Size of OctetString object: " << sizeof(res->m_pduSession->upTunnel.address) << " bytes" << std::endl;
        // Assuming m.m_pduSession->upTunnel.address is an OctetString
        for (size_t i = 0; i < sizeof(res->m_pduSession->upTunnel.address); ++i) {
            if (i != 0) {
                std::cout << ".";
            }
            std::cout << static_cast<int>(res->m_pduSession->upTunnel.address.data()[i]);
        }
        std::cout << std::endl;


        // Read GtpTunnel downTunnel
        res->m_pduSession->downTunnel.teid = stream.read4UI();
        std::cout<<"res->m_pduSession->downTunnel.teid: "<<res->m_pduSession->downTunnel.teid<<std::endl;
        res->m_pduSession->downTunnel.address = stream.readOctetString(stream.read4I());
        std::cout << "Size of OctetString object: " << sizeof(res->m_pduSession->downTunnel.address) << " bytes" << std::endl;
        for (size_t i = 0; i < sizeof(res->m_pduSession->downTunnel.address); ++i) {
            if (i != 0) {
                std::cout << ".";
            }
            std::cout << static_cast<int>(res->m_pduSession->downTunnel.address.data()[i]);
        }
        std::cout << std::endl;
        // Read QoS Flows
        int qosFlowCount = stream.read4I();
        std::cout<<"List: "<<qosFlowCount<<std::endl;
        // Use the asn::Unique constructor to convert the raw pointer returned by asn::New into a unique_ptr
        asn::Unique<ASN_NGAP_QosFlowSetupRequestList> newQosFlows(asn::New<ASN_NGAP_QosFlowSetupRequestList>());

        // Assign the newQosFlows to m.m_pduSession->qosFlows using std::move
        res->m_pduSession->qosFlows = std::move(newQosFlows);
        res->m_pduSession->qosFlows->list.array = new ASN_NGAP_QosFlowSetupRequestItem*[qosFlowCount];
        res->m_pduSession->qosFlows->list.array[0] = new ASN_NGAP_QosFlowSetupRequestItem();
        for (int iQos = 0; iQos < static_cast<int>(qosFlowCount); iQos++) {
            // Store the raw pointer in the array
            res->m_pduSession->qosFlows->list.array[iQos]->qosFlowIdentifier = stream.read4I();
            std::cout<<"res->m_pduSession->qosFlows->list.array[iQos]->qosFlowIdentifier: "<<res->m_pduSession->qosFlows->list.array[iQos]->qosFlowIdentifier<<std::endl;
        }
        res->m_pduSession->qosFlows->list.count = qosFlowCount;

        nas::IEUeSecurityCapability ueSecCap = nas::IEUeSecurityCapability::Decode( stream, 4);
        res->m_ueSecurityCapability = std::move(ueSecCap);
        // Now `ueSecCap` contains the decoded security capability fields
        // and you can use it as needed in the further processing
        std::cout << "Decoded UE Security Capability: " << std::endl;
        std::cout << "5G_EA0: " << static_cast<int>(ueSecCap.b_5G_EA0) << std::endl;
        std::cout << "128_5G_EA1: " << static_cast<int>(ueSecCap.b_128_5G_EA1) << std::endl;
        // Output other fields similarly
        std::cout<<" Decoding is running@@@"<<std::endl;

        return res;

    }

    return nullptr;
}

} // namespace rls
