//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#pragma once

#include "types.hpp"

#include <utility>

#include <lib/app/cli_base.hpp>
#include <lib/app/cli_cmd.hpp>
#include <lib/asn/utils.hpp>
#include <lib/rls/rls_base.hpp>
#include <lib/rrc/rrc.hpp>
#include <lib/sctp/sctp.hpp>
#include <utils/network.hpp>
#include <utils/nts.hpp>
#include <utils/octet_string.hpp>
#include <utils/unique_buffer.hpp>
#include <lib/nas/ie4.hpp>

extern "C"
{
    struct ASN_NGAP_FiveG_S_TMSI;
    struct ASN_NGAP_TAIListForPaging;
}

namespace nr::gnb
{

struct NmGnbRlsToRrc : NtsMessage
{
    enum PR
    {
        SIGNAL_DETECTED,
        UPLINK_RRC,
	SIGNAL_LOST,
    } present;

    // SIGNAL_DETECTED
    // UPLINK_RRC
    int ueId{};
    int psi{};

    // UPLINK_RRC
    OctetString data;
    rrc::RrcChannel rrcChannel{};

    explicit NmGnbRlsToRrc(PR present) : NtsMessage(NtsMessageType::GNB_RLS_TO_RRC), present(present)
    {
    }
};

struct NmGnbRlsToGtp : NtsMessage
{
    enum PR
    {
        DATA_PDU_DELIVERY,
        //Urwah
        DATA_PDU_RELEASE,
    } present;

    // DATA_PDU_DELIVERY
    int ueId{};
    int psi{};
    OctetString pdu;
    
    explicit NmGnbRlsToGtp(PR present) : NtsMessage(NtsMessageType::GNB_RLS_TO_GTP), present(present)
    {
    }
};

struct NmGnbGtpToRls : NtsMessage
{
    enum PR
    {
        DATA_PDU_DELIVERY,

    } present;

    // DATA_PDU_DELIVERY
    int ueId{};
    int psi{};
    OctetString pdu{};
    //Urwah
    std::unordered_map<uint64_t, std::unique_ptr<PduSessionResource>> m_pduSession;



    explicit NmGnbGtpToRls(PR present) : NtsMessage(NtsMessageType::GNB_GTP_TO_RLS), present(present)
    {
    }
};
//Urwah
struct NmGnbGtpToNgap : NtsMessage
{
    enum PR
    {
        //Urwah
        DATA_PDU_INFO,
    } present;

    // DATA_PDU_DELIVERY
    int ueId{};
    int psi{};
    //OctetString pdu{};

    //Urwah
    std::unique_ptr<PduSessionResource> m_pduSession;


    explicit NmGnbGtpToNgap(PR present) : NtsMessage(NtsMessageType::GNB_GTP_TO_NGAP), present(present)
    {
    }
};
//Urwah
struct NmGnbNgapToRls : NtsMessage
{
    enum PR
    {
        //Urwah
        DATA_PDU_INFO,
	XN_SESSION_CREATE,
    } present;

    // DATA_PDU_DELIVERY
    int ueId{};
    int psi{};
    //OctetString pdu{};
    int amfId{};
    //Urwah
    std::unique_ptr<PduSessionResource> m_pduSession;


    explicit NmGnbNgapToRls(PR present) : NtsMessage(NtsMessageType::GNB_NGAP_TO_RLS), present(present)
    {
    }
};

struct NmGnbRlsToRls : NtsMessage
{
    enum PR
    {
        SIGNAL_DETECTED,
        SIGNAL_LOST,
        RECEIVE_RLS_MESSAGE,
        DOWNLINK_RRC,
        DOWNLINK_DATA,
        UPLINK_RRC,
        UPLINK_DATA,
        RADIO_LINK_FAILURE,
        TRANSMISSION_FAILURE,
        //Urwah
        DOWNLINK_SESSION,
        SESSION_CHANGE,
        DOWNLINK_XN_DATA,
        SESSION_TRANSMISSION,
    } present;

    // SIGNAL_DETECTED
    // SIGNAL_LOST
    // DOWNLINK_RRC
    // DOWNLINK_DATA
    // UPLINK_DATA
    // UPLINK_RRC
    int ueId{};

    // RECEIVE_RLS_MESSAGE
    std::unique_ptr<rls::RlsMessage> msg{};

    // DOWNLINK_DATA
    // UPLINK_DATA
    int psi{};
    //Urwah
    std::unique_ptr<PduSessionResource> m_pduSession;
    int amfId;

    // DOWNLINK_DATA
    // DOWNLINK_RRC
    // UPLINK_DATA
    // UPLINK_RRC
    OctetString data;

    // DOWNLINK_RRC
    uint32_t pduId{};

    // DOWNLINK_RRC
    // UPLINK_RRC
    rrc::RrcChannel rrcChannel{};

    // RADIO_LINK_FAILURE
    rls::ERlfCause rlfCause{};

    // TRANSMISSION_FAILURE
    std::vector<rls::PduInfo> pduList;

    //Urwah
    nas::IEUeSecurityCapability m_ueSecurityCapability;


    explicit NmGnbRlsToRls(PR present) : NtsMessage(NtsMessageType::GNB_RLS_TO_RLS), present(present)
    {
    }
};

struct NmGnbRrcToRls : NtsMessage
{
    enum PR
    {
        RRC_PDU_DELIVERY,
    } present;

    // RRC_PDU_DELIVERY
    int ueId{};
    rrc::RrcChannel channel{};
    OctetString pdu{};

    explicit NmGnbRrcToRls(PR present) : NtsMessage(NtsMessageType::GNB_RRC_TO_RLS), present(present)
    {
    }
};

//Urwah
struct NmGnbRlsToNgap : NtsMessage
{
    enum PR
    {
        PACKET_SWITCH_REQUEST,
    } present;

    // RRC_PDU_DELIVERY
    int ueId{};
    //Urwah
    std::unique_ptr<PduSessionResource> m_pduSession;
    int psi{};
    int amfId{};

    OctetString pdu{};
    nas::IEUeSecurityCapability m_ueSecurityCapability;

    explicit NmGnbRlsToNgap(PR present) : NtsMessage(NtsMessageType::GNB_RLS_TO_NGAP), present(present)
    {
    }
};

struct NmGnbNgapToRrc : NtsMessage
{
    enum PR
    {
        RADIO_POWER_ON,
        NAS_DELIVERY,
        AN_RELEASE,
        PAGING,
    } present;

    // NAS_DELIVERY
    // AN_RELEASE
    int ueId{};

    // NAS_DELIVERY
    OctetString pdu{};

    // PAGING
    asn::Unique<ASN_NGAP_FiveG_S_TMSI> uePagingTmsi{};
    asn::Unique<ASN_NGAP_TAIListForPaging> taiListForPaging{};

    explicit NmGnbNgapToRrc(PR present) : NtsMessage(NtsMessageType::GNB_NGAP_TO_RRC), present(present)
    {
    }
};

struct NmGnbRrcToNgap : NtsMessage
{
    enum PR
    {
        INITIAL_NAS_DELIVERY,
        UPLINK_NAS_DELIVERY,
        RADIO_LINK_FAILURE,
	    SIGNAL_LOST,
    } present;

    // INITIAL_NAS_DELIVERY
    // UPLINK_NAS_DELIVERY
    // RADIO_LINK_FAILURE
    int ueId{};
    int psi{};
    // INITIAL_NAS_DELIVERY
    // UPLINK_NAS_DELIVERY
    OctetString pdu{};

    // INITIAL_NAS_DELIVERY
    int64_t rrcEstablishmentCause{};
    std::optional<GutiMobileIdentity> sTmsi{};

    explicit NmGnbRrcToNgap(PR present) : NtsMessage(NtsMessageType::GNB_RRC_TO_NGAP), present(present)
    {
    }
};

struct NmGnbNgapToGtp : NtsMessage
{
    enum PR
    {
        UE_CONTEXT_UPDATE,
        UE_CONTEXT_RELEASE,
        SESSION_CREATE,
        SESSION_RELEASE,
    } present;

    // UE_CONTEXT_UPDATE
    std::unique_ptr<GtpUeContextUpdate> update{};

    // SESSION_CREATE
    PduSessionResource *resource{};

    // UE_CONTEXT_RELEASE
    // SESSION_RELEASE
    int ueId{};

    // SESSION_RELEASE
    int psi{};

    explicit NmGnbNgapToGtp(PR present) : NtsMessage(NtsMessageType::GNB_NGAP_TO_GTP), present(present)
    {
    }
};
//Urwah
/*struct NmGnbNgapToRls : NtsMessage
{
    enum PR
    {
        XN_SESSION_CREATE,
    } present;


    // UE_CONTEXT_RELEASE
    // SESSION_RELEASE
    int ueId{};
    // SESSION_RELEASE
    int psi{};

    explicit NmGnbNgapToRls(PR present) : NtsMessage(NtsMessageType::GNB_NGAP_TO_RLS), present(present)
    {
    }
};*/
struct NmGnbSctp : NtsMessage
{
    enum PR
    {
        CONNECTION_REQUEST,
        CONNECTION_CLOSE,
        ASSOCIATION_SETUP,
        ASSOCIATION_SHUTDOWN,
        RECEIVE_MESSAGE,
        SEND_MESSAGE,
        UNHANDLED_NOTIFICATION,
    } present;

    // CONNECTION_REQUEST
    // CONNECTION_CLOSE
    // ASSOCIATION_SETUP
    // ASSOCIATION_SHUTDOWN
    // RECEIVE_MESSAGE
    // SEND_MESSAGE
    // UNHANDLED_NOTIFICATION
    int clientId{};

    // CONNECTION_REQUEST
    std::string localAddress{};
    uint16_t localPort{};
    std::string remoteAddress{};
    uint16_t remotePort{};
    sctp::PayloadProtocolId ppid{};
    NtsTask *associatedTask{};

    // ASSOCIATION_SETUP
    int associationId{};
    int inStreams{};
    int outStreams{};

    // RECEIVE_MESSAGE
    // SEND_MESSAGE
    UniqueBuffer buffer{};
    uint16_t stream{};

    explicit NmGnbSctp(PR present) : NtsMessage(NtsMessageType::GNB_SCTP), present(present)
    {
    }
};

struct NmGnbStatusUpdate : NtsMessage
{
    static constexpr const int NGAP_IS_UP = 1;

    const int what;

    // NGAP_IS_UP
    bool isNgapUp{};

    explicit NmGnbStatusUpdate(const int what) : NtsMessage(NtsMessageType::GNB_STATUS_UPDATE), what(what)
    {
    }
};

struct NmGnbCliCommand : NtsMessage
{
    std::unique_ptr<app::GnbCliCommand> cmd;
    InetAddress address;

    NmGnbCliCommand(std::unique_ptr<app::GnbCliCommand> cmd, InetAddress address)
        : NtsMessage(NtsMessageType::GNB_CLI_COMMAND), cmd(std::move(cmd)), address(address)
    {
    }
};

} // namespace nr::gnb
