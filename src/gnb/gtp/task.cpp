//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "task.hpp"

#include <gnb/gtp/proto.hpp>
#include <gnb/rls/task.hpp>
#include <utils/constants.hpp>
#include <utils/libc_error.hpp>

#include <asn/ngap/ASN_NGAP_QosFlowSetupRequestItem.h>
#include <cstdlib>
#include <string>
#include <iostream>

namespace nr::gnb
{

GtpTask::GtpTask(TaskBase *base)
    : m_base{base}, m_udpServer{}, m_ueContexts{}, m_rateLimiter(std::make_unique<RateLimiter>()), m_pduSessions{},
      m_sessionTree{}
{
    m_logger = m_base->logBase->makeUniqueLogger("gtp");
}

void GtpTask::onStart()
{
    try
    {
        m_udpServer = new udp::UdpServerTask(m_base->config->gtpIp, cons::GtpPort, this);
        m_udpServer->start();
    }
    catch (const LibError &e)
    {
        m_logger->err("GTP/UDP task could not be created. %s", e.what());
    }
}

void GtpTask::onQuit()
{
    m_udpServer->quit();
    delete m_udpServer;

    m_ueContexts.clear();
}

void GtpTask::onLoop()
{
    auto msg = take();
    if (!msg)
        return;

    switch (msg->msgType)
    {
    case NtsMessageType::GNB_NGAP_TO_GTP: {
        auto &w = dynamic_cast<NmGnbNgapToGtp &>(*msg);
        switch (w.present)
        {
        case NmGnbNgapToGtp::UE_CONTEXT_UPDATE: {
            handleUeContextUpdate(*w.update);
            break;
        }
        case NmGnbNgapToGtp::UE_CONTEXT_RELEASE: {
            handleUeContextDelete(w.ueId);
            break;
        }
        case NmGnbNgapToGtp::SESSION_CREATE: {
            handleSessionCreate(w.resource);
            break;
        }
        case NmGnbNgapToGtp::SESSION_RELEASE: {
            handleSessionRelease(w.ueId, w.psi);
            break;
        }
        }
        break;
    }
    case NtsMessageType::GNB_RLS_TO_GTP: {
        auto &w = dynamic_cast<NmGnbRlsToGtp &>(*msg);
        switch (w.present)
        {
        case NmGnbRlsToGtp::DATA_PDU_DELIVERY: {
            handleUplinkData(w.ueId, w.psi, std::move(w.pdu));
            break;
        }
        }
        break;
    }
    //Urwah
    /*case NtsMessageType::GNB_GTP_TO_RLS:{
        auto &w = dynamic_cast<NmGnbGtpToRls &>(*msg); 
        switch (w.present)
        {
            case NmGnbGtpToRls::DATA_PDU_RELEASE: {
                auto m = std::make_unique<NmGnbGtpToRls>(NmGnbGtpToRls::DATA_PDU_RELEASE);
                //m->
            }
        }
    }*/
    case NtsMessageType::UDP_SERVER_RECEIVE:
        handleUdpReceive(dynamic_cast<udp::NwUdpServerReceive &>(*msg));
        break;
    default:
        m_logger->unhandledNts(*msg);
        break;
    }
}

void GtpTask::handleUeContextUpdate(const GtpUeContextUpdate &msg)
{
    if (!m_ueContexts.count(msg.ueId))
        m_ueContexts[msg.ueId] = std::make_unique<GtpUeContext>(msg.ueId);

    auto &ue = m_ueContexts[msg.ueId];
    ue->ueAmbr = msg.ueAmbr;

    updateAmbrForUe(ue->ueId);
}

void GtpTask::handleSessionCreate(PduSessionResource *session)
{
    if (!m_ueContexts.count(session->ueId))
    {
        m_logger->err("PDU session resource could not be created, UE context with ID[%d] not found", session->ueId);
        return;
    }
    m_logger->info("New session created. ");
    uint64_t sessionInd = MakeSessionResInd(session->ueId, session->psi);
    m_pduSessions[sessionInd] = std::unique_ptr<PduSessionResource>(session);
    std::cout<<"Create function Session->upTunnel.address: ";
    for (size_t i = 0; i < sizeof(m_pduSessions[sessionInd]->upTunnel.address); ++i) {
    if (i != 0) {
        std::cout << ".";
    }
    std::cout << static_cast<int>(m_pduSessions[sessionInd]->upTunnel.address.data()[i]);
    }
    std::cout << std::endl;

    for (size_t i = 0; i < sizeof(m_pduSessions[sessionInd]->downTunnel.address); ++i) {
    if (i != 0) {
        std::cout << ".";
    }
    std::cout << static_cast<int>(m_pduSessions[sessionInd]->downTunnel.address.data()[i]);
    }
    std::cout << std::endl;

    std::cout<<"New sesion wala function ha: "<<session->downTunnel.teid<<std::endl;
    std::cout<<"New sesion wala function ha: "<<session->sessionAmbr.ulAmbr<<std::endl;
    std::cout<<"New sesion wala function ha: "<<session->sessionAmbr.dlAmbr<<std::endl;

    std::cout<<"New sesion wala function ha ueid: "<<session->ueId<<std::endl;
    std::cout<<"New sesion wala function ha Psi: "<<session->psi<<std::endl;
    //std::cout<<"New sesion wala function ha sessionInd: "<<session->ueId<<std::endl;
    m_sessionTree.insert(sessionInd, session->downTunnel.teid);
    std::cout<<"New sesion 1"<<std::endl;
    updateAmbrForUe(session->ueId);
    std::cout<<"New sesion 2"<<std::endl;
    updateAmbrForSession(sessionInd);
}

void GtpTask::handleSessionRelease(int ueId, int psi)
{
    if (!m_ueContexts.count(ueId))
    {
        m_logger->err("PDU session resource could not be released, UE context with ID[%d] not found", ueId);
        return;
    }

    uint64_t sessionInd = MakeSessionResInd(ueId, psi);

    // Remove all session information from rate limiter
    m_rateLimiter->updateSessionUplinkLimit(sessionInd, 0);
    m_rateLimiter->updateUeDownlinkLimit(ueId, 0);

    // And remove from PDU session table
    if (m_pduSessions.count(sessionInd))
    {
        uint32_t teid = m_pduSessions[sessionInd]->downTunnel.teid;
        m_pduSessions.erase(sessionInd);

        // And remove from the tree
        m_sessionTree.remove(sessionInd, teid);
    }
}

void GtpTask::handleUeContextDelete(int ueId)
{
    // Find PDU sessions of the UE
    std::vector<uint64_t> sessions{};
    m_sessionTree.enumerateByUe(ueId, sessions);

    for (auto &session : sessions)
    {
        // Remove all session information from rate limiter
        m_rateLimiter->updateSessionUplinkLimit(session, 0);
        m_rateLimiter->updateUeDownlinkLimit(ueId, 0);

        // And remove from PDU session table
        uint32_t teid = m_pduSessions[session]->downTunnel.teid;
        m_pduSessions.erase(session);

        // And remove from the tree
        m_sessionTree.remove(session, teid);
    }

    // Remove all user information from rate limiter
    m_rateLimiter->updateUeUplinkLimit(ueId, 0);
    m_rateLimiter->updateUeDownlinkLimit(ueId, 0);

    // Remove UE context
    m_ueContexts.erase(ueId);
}

void GtpTask::handleUplinkData(int ueId, int psi, OctetString &&pdu)
{
    const uint8_t *data = pdu.data();
    std::cout<<"Uplink data receive here!!!! "<<std::endl;
    // ignore non IPv4 packets
    if ((data[0] >> 4 & 0xF) != 4)
        {std::cout<<1<<std::endl;
        return;}
    std::cout<<"Ueid: "<<ueId<<std::endl;
    std::cout<<"Psi: "<<psi<<std::endl;

    uint64_t sessionInd = MakeSessionResInd(ueId, psi);

    if (!m_pduSessions.count(sessionInd))
    {
        m_logger->err("Uplink data failure, PDU session not found. UE[%d] PSI[%d]", ueId, psi);
        /*std::string command;
        command = "echo 1 > /proc/sys/net/ipv4/ip_forward";
        system(command.c_str());

        command = "sudo iptables -t nat -A PREROUTING -s 172.45.1.113 -j DNAT --to-destination 10.0.3.12";
        system(command.c_str());
        command = "sudo ip route add 10.0.5.12 via 10.101.1.4 dev eth2";
        system(command.c_str());*/
        return;
    }

    auto &pduSession = m_pduSessions[sessionInd];
    std::cout<<"pduSession->upTunnel.address: ";
    for (size_t i = 0; i < sizeof(pduSession->upTunnel.address); ++i) {
    if (i != 0) {
        std::cout << ".";
    }
    std::cout << static_cast<int>(pduSession->upTunnel.address.data()[i]);
    }
    std::cout << std::endl;
    std::cout<<"pduSession->downTunnel.address: ";
    for (size_t i = 0; i < sizeof(pduSession->downTunnel.address); ++i) {
    if (i != 0) {
        std::cout << ".";
    }
    std::cout << static_cast<int>(pduSession->downTunnel.address.data()[i]);
    }
    std::cout << std::endl;
    if (m_rateLimiter->allowUplinkPacket(sessionInd, static_cast<int64_t>(pdu.length())))
    {
        gtp::GtpMessage gtp{};
        gtp.payload = std::move(pdu);
        gtp.msgType = gtp::GtpMessage::MT_G_PDU;
        gtp.teid = pduSession->upTunnel.teid;
        std::cout<<"gtp.teid: "<<gtp.teid<<std::endl;
        std::cout<<"gtp.teid: "<<pduSession->downTunnel.teid<<std::endl;
        std::cout<<"pduSession->upTunnel.address: ";
        for (size_t i = 0; i < sizeof(pduSession->upTunnel.address); ++i) {
        if (i != 0) {
            std::cout << ".";
        }
        std::cout << static_cast<int>(pduSession->upTunnel.address.data()[i]);
        }
        std::cout << std::endl;
        std::cout<<"pduSession->downTunnel.address: ";
        for (size_t i = 0; i < sizeof(pduSession->downTunnel.address); ++i) {
        if (i != 0) {
            std::cout << ".";
        }
        std::cout << static_cast<int>(pduSession->downTunnel.address.data()[i]);
        }
        std::cout << std::endl;

        auto ul = std::make_unique<gtp::UlPduSessionInformation>();
        // TODO: currently using first QSI
        ul->qfi = static_cast<int>(pduSession->qosFlows->list.array[0]->qosFlowIdentifier);

        auto cont = std::make_unique<gtp::PduSessionContainerExtHeader>();
        cont->pduSessionInformation = std::move(ul);
        gtp.extHeaders.push_back(std::move(cont));

        OctetString gtpPdu;
        if (!gtp::EncodeGtpMessage(gtp, gtpPdu))
            m_logger->err("Uplink data failure, GTP encoding failed");
        else
            {std::cout<<3<<std::endl;
            std::cout<<"pduSession->upTunnel.address: ";
            for (size_t i = 0; i < sizeof(pduSession->upTunnel.address); ++i) {
            if (i != 0) {
                std::cout << ".";
            }
            std::cout << static_cast<int>(pduSession->upTunnel.address.data()[i]);
            }
            std::cout << std::endl;

            m_udpServer->send(InetAddress(pduSession->upTunnel.address, cons::GtpPort), gtpPdu);}
    }
}

void GtpTask::handleUdpReceive(const udp::NwUdpServerReceive &msg)
{
    OctetView buffer{msg.packet};
    auto gtp = gtp::DecodeGtpMessage(buffer);

    switch (gtp->msgType)
    {
    case gtp::GtpMessage::MT_G_PDU: {
        auto sessionInd = m_sessionTree.findByDownTeid(gtp->teid);
        if (sessionInd == 0)
        {
            m_logger->err("TEID %d not found on GTP-U Downlink", gtp->teid);
            return;
        }

        if (m_rateLimiter->allowDownlinkPacket(sessionInd, gtp->payload.length()))
        {
            auto w = std::make_unique<NmGnbGtpToRls>(NmGnbGtpToRls::DATA_PDU_DELIVERY);
            w->ueId = GetUeId(sessionInd);
            w->psi = GetPsi(sessionInd);
            w->pdu = std::move(gtp->payload);
            m_base->rlsTask->push(std::move(w));
        }
        return;
    }
    case gtp::GtpMessage::MT_ECHO_REQUEST: {
        gtp::GtpMessage gtpResponse{};
        gtpResponse.msgType = gtp::GtpMessage::MT_ECHO_RESPONSE;
        gtpResponse.seq = gtp->seq;
        gtpResponse.payload = OctetString::FromOctet2({14, 0});

        OctetString gtpPdu;
        if (gtp::EncodeGtpMessage(gtpResponse, gtpPdu))
            m_udpServer->send(msg.fromAddress, gtpPdu);
        else
            m_logger->err("Uplink data failure, GTP encoding failed");
        return;
    }
    default: {
        m_logger->err("Unhandled GTP-U message type: %d", gtp->msgType);
        return;
    }
    }
}

void GtpTask::updateAmbrForUe(int ueId)
{
    std::cout<<"New sesion 3"<<std::endl;
    if (!m_ueContexts.count(ueId))
        {std::cout<<"UpdateAmbr for Ue not worked!!!!"<<std::endl;
        return;}
    std::cout<<"New sesion 5"<<std::endl;
    auto &ue = m_ueContexts[ueId];
    std::cout<<"UE ALLA de!!! "<<ue->ueAmbr.ulAmbr<<std::endl;
    std::cout<<"UE ALLA de!!! "<<ue->ueAmbr.dlAmbr<<std::endl;
    m_rateLimiter->updateUeUplinkLimit(ueId, ue->ueAmbr.ulAmbr);
    m_rateLimiter->updateUeDownlinkLimit(ueId, ue->ueAmbr.dlAmbr);
}

void GtpTask::updateAmbrForSession(uint64_t pduSession)
{
    std::cout<<"New sesion 4"<<std::endl;
    if (!m_pduSessions.count(pduSession))
        {std::cout<<"UpdateAmbrForSession for Ue not worked!!!!"<<std::endl;
        return;}
    std::cout<<"New sesion 6"<<std::endl;
    auto &sess = m_pduSessions[pduSession];
    std::cout<<"ALLA de!!! "<<sess->sessionAmbr.ulAmbr<<std::endl;
    std::cout<<"ALLA de!!! "<<sess->sessionAmbr.dlAmbr<<std::endl;
    m_rateLimiter->updateSessionUplinkLimit(pduSession, sess->sessionAmbr.ulAmbr);
    m_rateLimiter->updateSessionDownlinkLimit(pduSession, sess->sessionAmbr.dlAmbr);
}

} // namespace nr::gnb
