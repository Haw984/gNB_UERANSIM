//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "task.hpp"
#include "utils.hpp"
#include <sstream>

#include <gnb/app/task.hpp>
#include <gnb/sctp/task.hpp>
#include <iostream>
#include <gnb/gtp/task.hpp>  
//std::unique_ptr<nr::gnb::PduSessionResource> nr::gnb::NgapTask::m_pathSwitchPduSession = nullptr;
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
	    std::cout<<"Receive Message task.cpp"<<std::endl;
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
    case NtsMessageType::GNB_RLS_TO_NGAP: {
        auto &w = dynamic_cast<NmGnbRlsToNgap &>(*msg);
        switch (w.present)
        {
            case NmGnbRlsToNgap::PACKET_SWITCH_REQUEST: {
                std::cout<<"$$$$$$$NGAP pohnch gya$$$$$$$$$$$"<<std::endl;
                //m_pathSwitchReq = true;
                std::cout << "Ueid: " << w.m_pduSession->ueId << std::endl;
                std::cout << "Psi: " << w.m_pduSession->psi << std::endl;
                if (w.m_pduSession) {
                    std::cout << "m_pduSession is valid." << std::endl;
                } else {
                    std::cerr << "m_pduSession is nullptr!" << std::endl;
                    return;  // Prevent further operations that would cause a crash
                }

                if (m_pathSwitchPduSession) {
                    std::cerr << "m_pathSwitchPduSession is not initialized or has been moved!" << std::endl;
                    //m_pathSwitchPduSession = std::make_unique<nr::gnb::PduSessionResource>(w.m_pduSession->ueId, w.m_pduSession->psi);
                }
                std::cout << "downTunnel TEID: " << w.m_pduSession->downTunnel.teid << std::endl;
                std::cout << "upTunnel TEID: " << w.m_pduSession->upTunnel.teid << std::endl;

                //m_pathSwitchPduSession = std::make_unique<nr::gnb::PduSessionResource>(w.m_pduSession->ueId, w.m_pduSession->psi);
                std::cout << "downTunnel TEID: " << w.m_pduSession->downTunnel.teid << std::endl;
                std::cout << "upTunnel TEID: " << w.m_pduSession->upTunnel.teid << std::endl;
                for (size_t i = 0; i < sizeof( w.m_pduSession->downTunnel.address); ++i) {
                    if (i != 0) {
                        std::cout << ".";
                    }
                    std::cout << static_cast<int>( w.m_pduSession->downTunnel.address.data()[i]);
                }
                std::string gtpIp = m_base->config->gtpAdvertiseIp.value_or(m_base->config->gtpIp);
                w.m_pduSession->downTunnel.address = utils::IpToOctetString(gtpIp);
                w.m_pduSession->downTunnel.teid = ++m_downlinkTeidCounter;

                // Print downTunnel TEID
                std::cout << "downTunnel TEID: " << w.m_pduSession->downTunnel.teid << std::endl;
                std::cout << "upTunnel TEID: " << w.m_pduSession->upTunnel.teid << std::endl;
                std::cout << "downTunnel address: "<< std::endl;

                for (size_t i = 0; i < sizeof( w.m_pduSession->downTunnel.address); ++i) {
                    if (i != 0) {
                        std::cout << ".";
                    }
                    std::cout << static_cast<int>( w.m_pduSession->downTunnel.address.data()[i]);
                }
                std::cout << "upTunnel address: "<< std::endl;

                for (size_t i = 0; i < sizeof( w.m_pduSession->upTunnel.address); ++i) {
                    if (i != 0) {
                        std::cout << ".";
                    }
                    std::cout << static_cast<int>( w.m_pduSession->upTunnel.address.data()[i]);
                }
                std::cout << "w.pdusession address: "<< w.m_pduSession.get()<< std::endl;

                //m_pathSwitchPduSession = nullptr;
                std::cout<<"m_pathSwitchPduSession address: "<<m_pathSwitchPduSession<<std::endl;

                //m_pathSwitchPduSession = std::make_unique<nr::gnb::PduSessionResource>(w.m_pduSession->ueId, w.m_pduSession->psi);
                m_pathSwitchPduSession = w.m_pduSession.release();
                std::cout<<"m_pathSwitchPduSession address: "<<m_pathSwitchPduSession<<std::endl;

                std::cout<<"m_pathSwitchPduSession ueId: "<<m_pathSwitchPduSession->ueId<<std::endl;
                std::cout << "m_pathSwitchPduSession Psi: " << m_pathSwitchPduSession->psi << std::endl;

                std::cout << "m_pathSwitchPduSession downTunnel TEID: " << m_pathSwitchPduSession->downTunnel.teid << std::endl;
                std::cout << "m_pathSwitchPduSession upTunnel TEID: " << m_pathSwitchPduSession->upTunnel.teid << std::endl;
                for (size_t i = 0; i < sizeof( m_pathSwitchPduSession->downTunnel.address); ++i) {
                    if (i != 0) {
                        std::cout << ".";
                    }
                    std::cout << static_cast<int>( m_pathSwitchPduSession->downTunnel.address.data()[i]);
                }
                std::cout << "upTunnel address: "<< std::endl;

                for (size_t i = 0; i < sizeof( m_pathSwitchPduSession->upTunnel.address); ++i) {
                    if (i != 0) {
                        std::cout << ".";
                    }
                    std::cout << static_cast<int>( m_pathSwitchPduSession->upTunnel.address.data()[i]);
                }
                std::cout<<"m_pathSwitchPduSession: "<<m_pathSwitchPduSession->ueId<<std::endl;
                auto &qosList = m_pathSwitchPduSession->qosFlows->list;
                std::cout<<"m_pathSwitchPduSession List: "<<static_cast<int>(qosList.count)<<std::endl;
                handlePathSwitchRequest(w.ueId, w.amfId, *m_pathSwitchPduSession, w.m_ueSecurityCapability);
                break;
            }
            case NmGnbRlsToNgap::PATH_SWITCH_REQUEST_ACK: {
                m_logger->info("Path switch request acknowledgement received");
                break;
            }

        }
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
