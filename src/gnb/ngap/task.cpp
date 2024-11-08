//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//
#include <iostream>
#include "task.hpp"
#include "utils.hpp"
#include <sstream>

#include <gnb/app/task.hpp>
#include <gnb/sctp/task.hpp>

#include <gnb/rls/task.hpp>
#include <gnb/gtp/task.hpp>  

namespace nr::gnb
{

NgapTask::NgapTask(TaskBase *base) : m_base{base}, m_ueNgapIdCounter{}, m_downlinkTeidCounter{}, m_isInitialized{}, m_pathSwitchPduSession{}
{
    m_logger = base->logBase->makeUniqueLogger("ngap");
}

void NgapTask::onStart()
{

    for (auto &amfConfig : m_base->config->amfConfigs)
        createAmfContext(amfConfig);
    if (m_amfCtx.empty())
        m_logger->warn("No AMF configuration is provided");

    for (auto &amfCtx : m_amfCtx)
    {
        auto msg = std::make_unique<NmGnbSctp>(NmGnbSctp::CONNECTION_REQUEST);
        msg->clientId = amfCtx.second->ctxId;
        msg->localAddress = m_base->config->ngapIp;
        msg->localPort = 0;
        msg->remoteAddress = amfCtx.second->address;
        msg->remotePort = amfCtx.second->port;
        msg->ppid = sctp::PayloadProtocolId::NGAP;
        msg->associatedTask = this;
        m_base->sctpTask->push(std::move(msg));
    }
}

void NgapTask::onLoop()
{
    auto msg = take();
    if (!msg)
        return;

    switch (msg->msgType)
    {
    case NtsMessageType::GNB_RRC_TO_NGAP: {
        auto &w = dynamic_cast<NmGnbRrcToNgap &>(*msg);
        switch (w.present)
        {
        case NmGnbRrcToNgap::INITIAL_NAS_DELIVERY: {
            handleInitialNasTransport(w.ueId, w.pdu, w.rrcEstablishmentCause, w.sTmsi);
            break;
        }
        case NmGnbRrcToNgap::UPLINK_NAS_DELIVERY: {
            handleUplinkNasTransport(w.ueId, w.pdu);
            break;
        }
        case NmGnbRrcToNgap::RADIO_LINK_FAILURE: {
            handleRadioLinkFailure(w.ueId);
            break;
        }
        case NmGnbRrcToNgap::SIGNAL_LOST: {
            handleSignalLost(w.ueId, w.psi);
            break;
        }
        }
        break;
    }
    case NtsMessageType::GNB_SCTP: {
        auto &w = dynamic_cast<NmGnbSctp &>(*msg);
        switch (w.present)
        {
        case NmGnbSctp::ASSOCIATION_SETUP:
            handleAssociationSetup(w.clientId, w.associationId, w.inStreams, w.outStreams);
            break;
        case NmGnbSctp::RECEIVE_MESSAGE:
            handleSctpMessage(w.clientId, w.stream, w.buffer);
            break;
        case NmGnbSctp::ASSOCIATION_SHUTDOWN:
            handleAssociationShutdown(w.clientId);
            break;
        default:
            m_logger->unhandledNts(*msg);
            break;
        }
        break;
    }
    //Urwah
    case NtsMessageType::GNB_GTP_TO_NGAP: {
        auto &x = dynamic_cast<NmGnbGtpToNgap &>(*msg);    
        switch (x.present)
        { 
            case NmGnbGtpToNgap::DATA_PDU_INFO: {
                auto *ue = findUeContext(x.ueId);
                auto m = std::make_unique<NmGnbNgapToRls>(NmGnbNgapToRls::DATA_PDU_INFO);
                m->m_pduSession = std::move(x.m_pduSession);
                m->ueId = x.ueId;
                m->psi = x.psi;
                m->amfId = std::move(static_cast<int>(ue->amfUeNgapId));
                m_base->rlsTask->push(std::move(m));
                break;
            }
        }
        break;
    }
    case NtsMessageType::GNB_RLS_TO_NGAP: {
        auto &w = dynamic_cast<NmGnbRlsToNgap &>(*msg);
        switch (w.present)
        {
            case NmGnbRlsToNgap::PACKET_SWITCH_REQUEST: {
                std::string gtpIp = m_base->config->gtpAdvertiseIp.value_or(m_base->config->gtpIp);
                w.m_pduSession->downTunnel.address = utils::IpToOctetString(gtpIp);
                w.m_pduSession->downTunnel.teid = ++m_downlinkTeidCounter;
                m_pathSwitchPduSession = w.m_pduSession.release();
                handlePathSwitchRequest(w.ueId, w.amfId, *m_pathSwitchPduSession, w.m_ueSecurityCapability);
                break;
            }
        }
        break;
    }
    default: {        
        m_logger->unhandledNts(*msg);
        break;
    }
    }
}

void NgapTask::onQuit()
{
    for (auto &i : m_ueCtx)
        delete i.second;
    for (auto &i : m_amfCtx)
        delete i.second;
    m_ueCtx.clear();
    m_amfCtx.clear();
}

} // namespace nr::gnb
