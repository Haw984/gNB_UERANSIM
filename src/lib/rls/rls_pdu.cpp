//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "rls_pdu.hpp"
#include <utils/constants.hpp>
#include <iostream>
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
    else if (msg.msgType == EMessageType::SESSION_TRANSMISSION)
    {
        std::cout<<"msg.msgType == EMessageType::SESSION_TRANSMISSION"<<std::endl;
        auto &m = (const RlsSessionTransmission &)msg;
        //stream.appendOctet(static_cast<uint8_t>(m.pduType));
        if (m.m_pduSession > 0)
        {
            std::cout<<"Khali nai ha bhai"<<std::endl;
        }
        else
        {
            std::cout<<"Khali ha"<<std::endl;
        }
        stream.appendOctet4(m.pduId);
        stream.appendOctet4(m.payload);
        stream.appendOctet4(m.amfId);


        //serialize(stream, m_pduSession);
        //%%%%%%%%%%%%%%%%%%
        //size_t len = 0;
        auto &qosList = m.m_pduSession->qosFlows->list;
        /*len += sizeof(uint8_t); // Number of QoS Flows
        for (int iQos = 0; iQos < qosList.count; iQos++) {
            len += sizeof(uint8_t); // qosFlowIdentifier
            // Add length calculation for other fields in ASN_NGAP_QosFlowSetupRequestItem if necessary
        }*/
        //stream.appendOctet4(static_cast<uint32_t>(len));
        //@@@@@@@@@@@@@@@
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
        //int64_t address_size = sizeof(m.m_pduSession->upTunnel.address);

        //std::cout<<"Address: "<< address_size<<std::endl;
        stream.appendOctet4(m.m_pduSession->upTunnel.address.length());
        stream.append(m.m_pduSession->upTunnel.address);    // Serialize address
        std::cout<<"res->m_pduSession->upTunnel.teid: "<<m.m_pduSession->upTunnel.teid<<std::endl;
        std::cout << "Size of OctetString object: " << sizeof(m.m_pduSession->upTunnel.address) << " bytes" << std::endl;
        // Assuming m.m_pduSession->upTunnel.address is an OctetString
        for (size_t i = 0; i < sizeof(m.m_pduSession->upTunnel.address); ++i) {
            if (i != 0) {
                std::cout << ".";
            }
            std::cout << static_cast<int>(m.m_pduSession->upTunnel.address.data()[i]);
        }
        std::cout << std::endl;
 
        // Serialize GtpTunnel downTunnel
        stream.appendOctet4(m.m_pduSession->downTunnel.teid); // Serialize TEID
        stream.appendOctet4(m.m_pduSession->downTunnel.address.length());    // Serialize address
        stream.append(m.m_pduSession->downTunnel.address);    // Serialize address
        std::cout<<"res->m_pduSession->downTunnel.teid: "<<m.m_pduSession->downTunnel.teid<<std::endl;
        std::cout << "Size of OctetString object: " << sizeof(m.m_pduSession->downTunnel.address) << " bytes" << std::endl;
        // Assuming m.m_pduSession->upTunnel.address is an OctetString
        for (size_t i = 0; i < sizeof(m.m_pduSession->downTunnel.address); ++i) {
            if (i != 0) {
                std::cout << ".";
            }
            std::cout << static_cast<int>(m.m_pduSession->downTunnel.address.data()[i]);
        }
       std::cout<<"GTP Tunnel Address (hex): ";
        for (size_t i = 0; i < sizeof(m.m_pduSession->downTunnel.address); ++i) {
            printf("%02x ", m.m_pduSession->downTunnel.address.data()[i]);
        }
        std::cout << std::endl;

        stream.appendOctet4(static_cast<int>(qosList.count)); // Serialize the number of QoS Flows
        std::cout<<"List: "<<static_cast<int>(qosList.count)<<std::endl;
        for (int iQos = 0; iQos < static_cast<int>(qosList.count); iQos++) {
            stream.appendOctet4(static_cast<int>(qosList.array[iQos]->qosFlowIdentifier)); // Serialize QoS Flow Identifier
            std::cout<<"static_cast<int>(qosList.array[iQos]->qosFlowIdentifier)"<<static_cast<int>(qosList.array[iQos]->qosFlowIdentifier)<<std::endl;
            // Add serialization for other fields in ASN_NGAP_QosFlowSetupRequestItem if necessary
        }

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
    //Urwah
    else if (msgType == EMessageType::RELEASE_SESSION)
    {
        auto res = std::make_unique<RlsTerminateSession>(sti);
        res->pduId = stream.read4UI();
        res->psi = stream.read4UI();
        std::cout<<"res->pduId EMessageType::RELEASE_SESSION: "<< res->pduId<<std::endl;
        return res;
    }

    return nullptr;
}

} // namespace rls


/*void serialize(OctetString &stream, std::unique_ptr<nr::gnb::PduSessionResource> m_pduSession) {
    // Serialize the provided ueId and psi
    stream.appendOctet4(static_cast<uint32_t>(m_pduSession.ueId)); // Serialize ueId
    stream.appendOctet4(static_cast<uint32_t>(m_pduSession.psi));  // Serialize psi

    // Serialize AggregateMaximumBitRate
    stream.appendOctet8(m_pduSession.sessionAmbr.dlAmbr); // Serialize dlAmbr
    stream.appendOctet8(m_pduSession.sessionAmbr.ulAmbr); // Serialize ulAmbr

    // Serialize boolean as a single byte
    stream.appendOctet(static_cast<uint8_t>(m_pduSession.dataForwardingNotPossible));

    // Serialize PduSessionType as a single byte
    stream.appendOctet(static_cast<uint8_t>(m_pduSession.sessionType));

    // Serialize GtpTunnel upTunnel
    stream.appendOctet4(m_pduSession.upTunnel.teid); // Serialize TEID
    stream.append(m_pduSession.upTunnel.address);    // Serialize address

    // Serialize GtpTunnel downTunnel
    stream.appendOctet4(m_pduSession.downTunnel.teid); // Serialize TEID
    stream.append(m_pduSession.downTunnel.address);    // Serialize address

    // Serialize QoS Flows
    auto &qosList = m_pduSession.qosFlows->list;
    stream.appendOctet(static_cast<uint8_t>(qosList.count)); // Serialize the number of QoS Flows
    for (int iQos = 0; iQos < qosList.count; iQos++) {
        stream.appendOctet(static_cast<uint8_t>(qosList.array[iQos]->qosFlowIdentifier)); // Serialize QoS Flow Identifier
        // Add serialization for other fields in ASN_NGAP_QosFlowSetupRequestItem if necessary
    }
}

size_t calculatePduSessionResourceLength( std::unique_ptr<nr::gnb::PduSessionResource> &resource) {
    size_t len = 0;

    // Add length of primitive types
    len += sizeof(uint32_t); // ueId
    len += sizeof(uint32_t); // psi

    // Add length of AggregateMaximumBitRate
    len += sizeof(uint64_t); // dlAmbr
    len += sizeof(uint64_t); // ulAmbr

    // Add length for boolean and PduSessionType
    len += sizeof(uint8_t); // dataForwardingNotPossible
    len += sizeof(uint8_t); // sessionType

    // Add length of GtpTunnel
    len += sizeof(uint32_t); // TEID
    len += resource.upTunnel.address.length(); // Address length

    len += sizeof(uint32_t); // TEID
    len += resource.downTunnel.address.length(); // Address length

    // Add length of ASN_NGAP_QosFlowSetupRequestList
    auto &qosList = resource.qosFlows->list;
    len += sizeof(uint8_t); // Number of QoS Flows
    for (int iQos = 0; iQos < qosList.count; iQos++) {
        len += sizeof(uint8_t); // qosFlowIdentifier
        // Add length calculation for other fields in ASN_NGAP_QosFlowSetupRequestItem if necessary
    }
    return len;
}*/