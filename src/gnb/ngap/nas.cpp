//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "encode.hpp"
#include "task.hpp"
#include "utils.hpp"

#include <gnb/rrc/task.hpp>

#include <asn/ngap/ASN_NGAP_DownlinkNASTransport.h>
#include <asn/ngap/ASN_NGAP_InitialUEMessage.h>
#include <asn/ngap/ASN_NGAP_InitiatingMessage.h>
#include <asn/ngap/ASN_NGAP_NASNonDeliveryIndication.h>
#include <asn/ngap/ASN_NGAP_NGAP-PDU.h>
#include <asn/ngap/ASN_NGAP_ProtocolIE-Field.h>
#include <asn/ngap/ASN_NGAP_RerouteNASRequest.h>
#include <asn/ngap/ASN_NGAP_UplinkNASTransport.h>
#include "asn/ngap/ASN_NGAP_UserLocationInformationNR.h"
#include "asn/ngap/ASN_NGAP_PDUSessionResourceToBeSwitchedDLItem.h"

//Urwah
#include <utils/octet_string.hpp>
#include <utils/octet_view.hpp>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceToBeSwitchedDLList.h>
#include <asn/ngap/ASN_NGAP_PathSwitchRequest.h>
#include <asn/ngap/ASN_NGAP_PathSwitchRequestTransfer.h>
#include "asn/ngap/ASN_NGAP_GTPTunnel.h"
#include "asn/ngap/ASN_NGAP_QosFlowAcceptedItem.h"
#include "asn/ngap/ASN_NGAP_QosFlowSetupRequestItem.h" // Adjust the path as necessary
#include <asn/ngap/ASN_NGAP_UESecurityCapabilities.h>
#include <asn/asn1c/OCTET_STRING.h>
#include <gnb/gtp/task.hpp>

#include <iostream>

#define MAX_LIST_SIZE 100 // Define an appropriate size based on your needs

namespace nr::gnb
{

void NgapTask::handleInitialNasTransport(int ueId, const OctetString &nasPdu, int64_t rrcEstablishmentCause,
                                         const std::optional<GutiMobileIdentity> &sTmsi)
{
    m_logger->debug("Initial NAS message received from UE[%d]", ueId);

    if (m_ueCtx.count(ueId))
    {
        m_logger->err("UE context[%d] already exists", ueId);
        return;
    }

    createUeContext(ueId);

    auto *ueCtx = findUeContext(ueId);
    if (ueCtx == nullptr)
        return;
    auto *amfCtx = findAmfContext(ueCtx->associatedAmfId);
    if (amfCtx == nullptr)
        return;

    if (amfCtx->state != EAmfState::CONNECTED)
    {
        m_logger->err("Initial NAS transport failure. AMF is not in connected state.");
        return;
    }

    amfCtx->nextStream = (amfCtx->nextStream + 1) % amfCtx->association.outStreams;
    if ((amfCtx->nextStream == 0) && (amfCtx->association.outStreams > 1))
        amfCtx->nextStream += 1;
    ueCtx->uplinkStream = amfCtx->nextStream;

    std::vector<ASN_NGAP_InitialUEMessage_IEs *> ies;

    //if (ASN_NGAP_InitialUEMessage_IEs__value_PR_RRCEstablishmentCause == "TAI_CHANGE_IN_ATT_UPD")
    //{
    //std::cout<<"ngap->nas.cpp, ASN_NGAP_InitialUEMessage_IEs__value_PR_RRCEstablishmentCause == TAI_CHANGE_IN_ATT_UPD"<<std::endl;
    //}
    auto *ieEstablishmentCause = asn::New<ASN_NGAP_InitialUEMessage_IEs>();
    ieEstablishmentCause->id = ASN_NGAP_ProtocolIE_ID_id_RRCEstablishmentCause;
    ieEstablishmentCause->criticality = ASN_NGAP_Criticality_ignore;
    ieEstablishmentCause->value.present = ASN_NGAP_InitialUEMessage_IEs__value_PR_RRCEstablishmentCause;
    ieEstablishmentCause->value.choice.RRCEstablishmentCause = rrcEstablishmentCause;
    ies.push_back(ieEstablishmentCause);

    auto *ieCtxRequest = asn::New<ASN_NGAP_InitialUEMessage_IEs>();
    ieCtxRequest->id = ASN_NGAP_ProtocolIE_ID_id_UEContextRequest;
    ieCtxRequest->criticality = ASN_NGAP_Criticality_ignore;
    ieCtxRequest->value.present = ASN_NGAP_InitialUEMessage_IEs__value_PR_UEContextRequest;
    ieCtxRequest->value.choice.UEContextRequest = ASN_NGAP_UEContextRequest_requested;
    ies.push_back(ieCtxRequest);

    auto *ieNasPdu = asn::New<ASN_NGAP_InitialUEMessage_IEs>();
    ieNasPdu->id = ASN_NGAP_ProtocolIE_ID_id_NAS_PDU;
    ieNasPdu->criticality = ASN_NGAP_Criticality_reject;
    ieNasPdu->value.present = ASN_NGAP_InitialUEMessage_IEs__value_PR_NAS_PDU;
    asn::SetOctetString(ieNasPdu->value.choice.NAS_PDU, nasPdu);
    ies.push_back(ieNasPdu);

    if (sTmsi)
    {
        auto *ieTmsi = asn::New<ASN_NGAP_InitialUEMessage_IEs>();
        ieTmsi->id = ASN_NGAP_ProtocolIE_ID_id_FiveG_S_TMSI;
        ieTmsi->criticality = ASN_NGAP_Criticality_reject;
        ieTmsi->value.present = ASN_NGAP_InitialUEMessage_IEs__value_PR_FiveG_S_TMSI;

        asn::SetBitStringInt<10>(sTmsi->amfSetId, ieTmsi->value.choice.FiveG_S_TMSI.aMFSetID);
        asn::SetBitStringInt<6>(sTmsi->amfPointer, ieTmsi->value.choice.FiveG_S_TMSI.aMFPointer);
        asn::SetOctetString4(ieTmsi->value.choice.FiveG_S_TMSI.fiveG_TMSI, sTmsi->tmsi);
        ies.push_back(ieTmsi);

    }

        auto *pdu = asn::ngap::NewMessagePdu<ASN_NGAP_InitialUEMessage>(ies);
        sendNgapUeAssociated(ueId, pdu);
}

void NgapTask::deliverDownlinkNas(int ueId, OctetString &&nasPdu)
{
    auto w = std::make_unique<NmGnbNgapToRrc>(NmGnbNgapToRrc::NAS_DELIVERY);
    w->ueId = ueId;
    w->pdu = std::move(nasPdu);
    m_base->rrcTask->push(std::move(w));
}

void NgapTask::handleUplinkNasTransport(int ueId, const OctetString &nasPdu)
{
    auto *ue = findUeContext(ueId);
    if (ue == nullptr)
        return;

    auto *ieNasPdu = asn::New<ASN_NGAP_UplinkNASTransport_IEs>();
    ieNasPdu->id = ASN_NGAP_ProtocolIE_ID_id_NAS_PDU;
    ieNasPdu->criticality = ASN_NGAP_Criticality_reject;
    ieNasPdu->value.present = ASN_NGAP_UplinkNASTransport_IEs__value_PR_NAS_PDU;
    asn::SetOctetString(ieNasPdu->value.choice.NAS_PDU, nasPdu);

    auto *pdu = asn::ngap::NewMessagePdu<ASN_NGAP_UplinkNASTransport>({ieNasPdu});
    sendNgapUeAssociated(ueId, pdu);
}

void NgapTask::sendNasNonDeliveryIndication(int ueId, const OctetString &nasPdu, NgapCause cause)
{
    m_logger->debug("Sending non-delivery indication for UE[%d]", ueId);

    auto *ieNasPdu = asn::New<ASN_NGAP_NASNonDeliveryIndication_IEs>();
    ieNasPdu->id = ASN_NGAP_ProtocolIE_ID_id_NAS_PDU;
    ieNasPdu->criticality = ASN_NGAP_Criticality_ignore;
    ieNasPdu->value.present = ASN_NGAP_NASNonDeliveryIndication_IEs__value_PR_NAS_PDU;
    asn::SetOctetString(ieNasPdu->value.choice.NAS_PDU, nasPdu);

    auto *ieCause = asn::New<ASN_NGAP_NASNonDeliveryIndication_IEs>();
    ieCause->id = ASN_NGAP_ProtocolIE_ID_id_Cause;
    ieCause->criticality = ASN_NGAP_Criticality_ignore;
    ieCause->value.present = ASN_NGAP_NASNonDeliveryIndication_IEs__value_PR_Cause;
    ngap_utils::ToCauseAsn_Ref(cause, ieCause->value.choice.Cause);

    auto *pdu = asn::ngap::NewMessagePdu<ASN_NGAP_NASNonDeliveryIndication>({ieNasPdu, ieCause});
    sendNgapUeAssociated(ueId, pdu);
}

void NgapTask::receiveDownlinkNasTransport(int amfId, ASN_NGAP_DownlinkNASTransport *msg)
{
    auto *ue = findUeByNgapIdPair(amfId, ngap_utils::FindNgapIdPair(msg));
    if (ue == nullptr)
        return;

    auto *ieNasPdu = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_NAS_PDU);
    if (ieNasPdu)
        deliverDownlinkNas(ue->ctxId, asn::GetOctetString(ieNasPdu->NAS_PDU));
}

void NgapTask::receiveRerouteNasRequest(int amfId, ASN_NGAP_RerouteNASRequest *msg)
{
    m_logger->debug("Reroute NAS request received");

    auto *ue = findUeByNgapIdPair(amfId, ngap_utils::FindNgapIdPair(msg));
    if (ue == nullptr)
        return;

    auto *ieNgapMessage = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_NGAP_Message);
    auto *ieAmfSetId = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_AMFSetID);
    auto *ieAllowedNssai = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_AllowedNSSAI);

    auto ngapPdu = asn::New<ASN_NGAP_NGAP_PDU>();
    ngapPdu->present = ASN_NGAP_NGAP_PDU_PR_initiatingMessage;
    ngapPdu->choice.initiatingMessage = asn::New<ASN_NGAP_InitiatingMessage>();
    ngapPdu->choice.initiatingMessage->procedureCode = ASN_NGAP_ProcedureCode_id_InitialUEMessage;
    ngapPdu->choice.initiatingMessage->criticality = ASN_NGAP_Criticality_ignore;
    ngapPdu->choice.initiatingMessage->value.present = ASN_NGAP_InitiatingMessage__value_PR_InitialUEMessage;

    auto *initialUeMessage = &ngapPdu->choice.initiatingMessage->value.choice.InitialUEMessage;

    if (!ngap_encode::DecodeInPlace(asn_DEF_ASN_NGAP_InitialUEMessage, ieNgapMessage->OCTET_STRING, &initialUeMessage))
    {
        m_logger->err("APER decoding failed in Reroute NAS Request");
        asn::Free(asn_DEF_ASN_NGAP_NGAP_PDU, ngapPdu);
        sendErrorIndication(amfId, NgapCause::Protocol_transfer_syntax_error);
        return;
    }

    if (ieAllowedNssai)
    {
        auto *oldAllowedNssai = asn::ngap::GetProtocolIe(initialUeMessage, ASN_NGAP_ProtocolIE_ID_id_AllowedNSSAI);
        if (oldAllowedNssai)
            asn::DeepCopy(asn_DEF_ASN_NGAP_AllowedNSSAI, ieAllowedNssai->AllowedNSSAI, &oldAllowedNssai->AllowedNSSAI);
        else
        {
            auto *newAllowedNssai = asn::New<ASN_NGAP_InitialUEMessage_IEs>();
            newAllowedNssai->id = ASN_NGAP_ProtocolIE_ID_id_AllowedNSSAI;
            newAllowedNssai->criticality = ASN_NGAP_Criticality_reject;
            newAllowedNssai->value.present = ASN_NGAP_InitialUEMessage_IEs__value_PR_AllowedNSSAI;

            asn::ngap::AddProtocolIe(*initialUeMessage, newAllowedNssai);
        }
    }

    auto *newAmf = selectNewAmfForReAllocation(ue->ctxId, amfId, asn::GetBitStringInt<10>(ieAmfSetId->AMFSetID));
    if (newAmf == nullptr)
    {
        m_logger->err("AMF selection for re-allocation failed. Could not find a suitable AMF.");
        return;
    }

    sendNgapUeAssociated(ue->ctxId, ngapPdu);
}
//Urwah
void NgapTask::handlePathSwitchRequest(int ueId, int amfId, const PduSessionResource &pduSessionResource, 
                                        const nas::IEUeSecurityCapability ueSecurityCapability)
{
    m_logger->debug("Path Switch Request received from UE[%d]", ueId);
    m_pathSwitchReqUeId = ueId;
    // Ensure UE context exists
    if (!m_ueCtx.count(ueId))
    {
        m_logger->info("UE context[%d] does not exist", ueId);
        createUeContext(ueId);
        //auto *ueCtx = findUeContext(ueId);
        //ueCtx->amfUeNgapId = ueCtx->associatedAmfId;
    }
    std::cout << "Added createUeContext to list" << std::endl;
    std::cout<< "amfId: "<<amfId<<std::endl;

    auto *ueCtx = findUeContext(ueId);
    if (ueCtx == nullptr)
    {
        m_logger->err("Failed to find UE context for UE[%d]", ueId);
        return;
    }
    if (ueCtx->amfUeNgapId == -1)
    {
        ueCtx->amfUeNgapId = amfId;
        std::cout<<"~~~~~~~~~~~~~~~~~~~~~~ue->amfUeNgapId == -1~~~~~~~~~~~~~~"<<std::endl;

    }
    auto *amfCtx = findAmfContext(ueCtx->associatedAmfId);
    std::cout<< "ue->amfUeNgapId: "<< amfCtx->ctxId<<std::endl;

    if (amfCtx == nullptr || amfCtx->state != EAmfState::CONNECTED)
    {
        m_logger->err("AMF context not found or not connected for UE[%d]", ueId);
        return;
    }
    std::cout << "Added findAmfContext to list" << std::endl;

    // Determine uplink stream
    amfCtx->nextStream = (amfCtx->nextStream + 1) % amfCtx->association.outStreams;
    if (amfCtx->nextStream == 0 && amfCtx->association.outStreams > 1)
        amfCtx->nextStream += 1;
    ueCtx->uplinkStream = amfCtx->nextStream;
    std::cout << "Added Determine uplink stream" << std::endl;

    auto w = std::make_unique<NmGnbNgapToGtp>(NmGnbNgapToGtp::UE_CONTEXT_UPDATE);
    ueCtx->ueAmbr.dlAmbr = pduSessionResource.sessionAmbr.dlAmbr;
    ueCtx->ueAmbr.ulAmbr = pduSessionResource.sessionAmbr.ulAmbr;
    w->update = std::make_unique<GtpUeContextUpdate>(true, ueCtx->ctxId, ueCtx->ueAmbr);
    m_base->gtpTask->push(std::move(w));

    // Prepare NGAP PDU for Path Switch Request
    auto *pdu = asn::New<ASN_NGAP_NGAP_PDU>();
    pdu->present = ASN_NGAP_NGAP_PDU_PR_initiatingMessage;
    pdu->choice.initiatingMessage = asn::New<ASN_NGAP_InitiatingMessage>();
    pdu->choice.initiatingMessage->procedureCode = ASN_NGAP_ProcedureCode_id_PathSwitchRequest;
    pdu->choice.initiatingMessage->criticality = ASN_NGAP_Criticality_reject;
    pdu->choice.initiatingMessage->value.present = ASN_NGAP_InitiatingMessage__value_PR_PathSwitchRequest;
    std::cout << "Added ASN_NGAP_NGAP_PDU" << std::endl;
 
    // Send the prepared Path Switch Request
    sendNgapUeAssociatedPathSwitchReq(ueId, pdu, pduSessionResource, ueSecurityCapability);
}
}


