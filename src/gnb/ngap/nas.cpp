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

void NgapTask::handlePathSwitchRequest(int ueId, const PduSessionResource &pduSessionResource, 
                                        const nas::IEUeSecurityCapability ueSecurityCapability)
{
    m_logger->debug("Path Switch Request received from UE[%d]", ueId);

    // Check if the UE context exists
    if (m_ueCtx.count(ueId))
    {
        m_logger->err("UE context[%d] already exist", ueId);
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
        m_logger->err("Path Switch Request failed. AMF is not in connected state.");
        return;
    }

    // Determine uplink stream
    amfCtx->nextStream = (amfCtx->nextStream + 1) % amfCtx->association.outStreams;
    if ((amfCtx->nextStream == 0) && (amfCtx->association.outStreams > 1))
        amfCtx->nextStream += 1;
    ueCtx->uplinkStream = amfCtx->nextStream;

    // Create list of IE elements for Path Switch Request message
    std::vector<ASN_NGAP_PathSwitchRequestIEs *> ies;

    // AMF UE NGAP ID
    auto *ieAmfUeNgapId = asn::New<ASN_NGAP_PathSwitchRequestIEs>();
    ieAmfUeNgapId->id = ASN_NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
    ieAmfUeNgapId->criticality = ASN_NGAP_Criticality_reject;
    ieAmfUeNgapId->value.present = ASN_NGAP_PathSwitchRequestIEs__value_PR_AMF_UE_NGAP_ID;
    asn::SetSigned64(ueCtx->amfUeNgapId, ieAmfUeNgapId->value.choice.AMF_UE_NGAP_ID);
    ies.push_back(ieAmfUeNgapId);

    // RAN UE NGAP ID
    auto *ieRanUeNgapId = asn::New<ASN_NGAP_PathSwitchRequestIEs>();
    ieRanUeNgapId->id = ASN_NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
    ieRanUeNgapId->criticality = ASN_NGAP_Criticality_reject;
    ieRanUeNgapId->value.present = ASN_NGAP_PathSwitchRequestIEs__value_PR_RAN_UE_NGAP_ID;
    ieRanUeNgapId->value.choice.RAN_UE_NGAP_ID = ueCtx->ranUeNgapId;
    ies.push_back(ieRanUeNgapId);

    // User location information
    auto *ieLocationInfo = asn::New<ASN_NGAP_PathSwitchRequestIEs>();
    ieLocationInfo->id = ASN_NGAP_ProtocolIE_ID_id_UserLocationInformation;
    ieLocationInfo->criticality = ASN_NGAP_Criticality_reject;
    ieLocationInfo->value.present = ASN_NGAP_PathSwitchRequestIEs__value_PR_UserLocationInformation;
    ieLocationInfo->value.choice.UserLocationInformation.present = ASN_NGAP_UserLocationInformation_PR_userLocationInformationNR;

    auto &locNr = ieLocationInfo->value.choice.UserLocationInformation.choice.userLocationInformationNR;
    locNr = asn::New<ASN_NGAP_UserLocationInformationNR>();
    ngap_utils::ToPlmnAsn_Ref(m_base->config->plmn, locNr->nR_CGI.pLMNIdentity);
    asn::SetBitStringLong<36>(m_base->config->nci, locNr->nR_CGI.nRCellIdentity);
    ngap_utils::ToPlmnAsn_Ref(m_base->config->plmn, locNr->tAI.pLMNIdentity);
    asn::SetOctetString3(locNr->tAI.tAC, octet3{m_base->config->tac});
    ies.push_back(ieLocationInfo);

   auto *pduSessionResourceList = asn::New<ASN_NGAP_PDUSessionResourceToBeSwitchedDLList>();

    // Initialize the list size and allocate memory for the array
    pduSessionResourceList->list.size = 1;  // Set an appropriate size (10 is just an example)
    pduSessionResourceList->list.count = 0;  // Initially, no items
    pduSessionResourceList->list.array = (ASN_NGAP_PDUSessionResourceToBeSwitchedDLItem **)
        calloc(pduSessionResourceList->list.size, sizeof(ASN_NGAP_PDUSessionResourceToBeSwitchedDLItem *));

    if (pduSessionResourceList->list.array == nullptr)
    {
        m_logger->err("Failed to allocate memory for PDUSessionResourceToBeSwitchedDLList");
        return;
    }

    // Create a new PDU Session Resource Item
    auto *pduSessionItem = asn::New<ASN_NGAP_PDUSessionResourceToBeSwitchedDLItem>();
    pduSessionItem->pDUSessionID = pduSessionResource.psi;

    // Set pathSwitchRequestTransfer with appropriate data
    OCTET_STRING_t pathSwitchRequestTransfer;
    pathSwitchRequestTransfer.buf = nullptr;  // Initialize to nullptr
    pathSwitchRequestTransfer.size = 0;      // Initialize size to 0
    pathSwitchRequestTransfer._asn_ctx = {};  // Initialize context if required
    pduSessionItem->pathSwitchRequestTransfer = pathSwitchRequestTransfer;

    // Add the item to the list
    size_t currentSize = pduSessionResourceList->list.count;
    if (currentSize < static_cast<size_t>(pduSessionResourceList->list.size))
    {
        pduSessionResourceList->list.array[currentSize] = pduSessionItem;
        pduSessionResourceList->list.count++;
    }
    else
    {
        m_logger->err("PDUSessionResourceToBeSwitchedDLList is full");
        return;
    }


    // Add list to IE elements
    auto *iePduSessionResourceList = asn::New<ASN_NGAP_PathSwitchRequestIEs>();
    iePduSessionResourceList->id = ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceToBeSwitchedDLList;
    iePduSessionResourceList->criticality = ASN_NGAP_Criticality_reject;
    iePduSessionResourceList->value.present = ASN_NGAP_PathSwitchRequestIEs__value_PR_PDUSessionResourceToBeSwitchedDLList;
    iePduSessionResourceList->value.choice.PDUSessionResourceToBeSwitchedDLList = *pduSessionResourceList;
    ies.push_back(iePduSessionResourceList);

    // Encode and send the Path Switch Request message
    auto *pdu = asn::ngap::NewMessagePdu<ASN_NGAP_PathSwitchRequest>(ies);
    //auto pduList = PDUSessionResourceToBeSwitchedDLList(pduSessionResource);
    sendNgapUeAssociatedPathSwitchReq(ueId, pdu, pduSessionResource, ueSecurityCapability) ;
}

/*ASN_NGAP_PDUSessionResourceToBeSwitchedDLList NgapTask::PDUSessionResourceToBeSwitchedDLList(const PduSessionResource& pduSessionResource) 
{
    auto pduList = std::make_unique<ASN_NGAP_PDUSessionResourceToBeSwitchedDLList>();
    
    pduList->list.count = 0;
    pduList->list.size = 1; // Assuming only one PDU session resource for now
    pduList->list.array = (ASN_NGAP_PDUSessionResourceToBeSwitchedDLItem **)calloc(pduList->list.size, sizeof(ASN_NGAP_PDUSessionResourceToBeSwitchedDLItem *));
    

    auto *item = asn::New<ASN_NGAP_PDUSessionResourceToBeSwitchedDLItem>();
    item->pDUSessionID = pduSessionResource.psi;
    OCTET_STRING_t octetString;
    // Initialize PathSwitchRequestTransfer and assign values
    auto *pathSwitchRequestTransfer = asn::New<ASN_NGAP_PathSwitchRequestTransfer>();

    // Initialize GTP Tunnel
    pathSwitchRequestTransfer->dL_NGU_UP_TNLInformation.present = ASN_NGAP_UPTransportLayerInformation_PR_gTPTunnel;
    pathSwitchRequestTransfer->dL_NGU_UP_TNLInformation.choice.gTPTunnel = asn::New<ASN_NGAP_GTPTunnel>();

    auto* gTPTunnel = pathSwitchRequestTransfer->dL_NGU_UP_TNLInformation.choice.gTPTunnel;
    const auto& address = pduSessionResource.upTunnel.address;
    gTPTunnel->transportLayerAddress.size = address.length();  // Use the correct method for size
    gTPTunnel->transportLayerAddress.buf = new uint8_t[gTPTunnel->transportLayerAddress.size];
    std::memcpy(gTPTunnel->transportLayerAddress.buf, address.data(), gTPTunnel->transportLayerAddress.size);  // Use the correct method for buffer

    gTPTunnel->gTP_TEID.size = sizeof(uint32_t);
    gTPTunnel->gTP_TEID.buf = new uint8_t[gTPTunnel->gTP_TEID.size];
    std::memcpy(gTPTunnel->gTP_TEID.buf, &pduSessionResource.upTunnel.teid, sizeof(uint32_t));
    std::cout<<"res->m_pduSession->upTunnel.teid: "<<pduSessionResource.upTunnel.teid<<std::endl;

    if (pduSessionResource.dataForwardingNotPossible)
    {
        pathSwitchRequestTransfer->userPlaneSecurityInformation = nullptr;
    }
    // Create and initialize QosFlowAcceptedList
    auto* qosFlowAcceptedList = asn::New<ASN_NGAP_QosFlowAcceptedList>();

    qosFlowAcceptedList->list.count = 0;
    qosFlowAcceptedList->list.count = pduSessionResource.qosFlows->list.count;
    std::cout<<"pduSessionResource.qosFlows->list.count = "<<pduSessionResource.qosFlows->list.count<<std::endl;                qosFlowAcceptedList->list.array = (ASN_NGAP_QosFlowAcceptedItem **)calloc(qosFlowAcceptedList->list.count, sizeof(ASN_NGAP_QosFlowAcceptedItem *));
    std::cout<<"static_cast<int>(qosList.array[iQos]->qosFlowIdentifier): "<<static_cast<int>(pduSessionResource.qosFlows->list.array[0]->qosFlowIdentifier)<<std::endl;


    // Add QoS Flow Accepted Items
    for (int i = 0; i < pduSessionResource.qosFlows->list.count; ++i) {
        const auto& qosFlowSetupRequestItem = *pduSessionResource.qosFlows->list.array[i];
        auto* acceptedItem = asn::New<ASN_NGAP_QosFlowAcceptedItem>();
        if (!acceptedItem) {
            std::cout<<"Failed to allocate memory for QosFlowAcceptedItem"<<"\n";
            continue;
        }

        // Copy data
        acceptedItem->qosFlowIdentifier = qosFlowSetupRequestItem.qosFlowIdentifier;
        
        std::cout<<"QoS Flow Accepted Item - QoS Flow Identifier: "<< i <<" " << acceptedItem->qosFlowIdentifier<< "\n";
        // Handle optional fields
        /*if (qosFlowSetupRequestItem.qosFlowLevelQosParameters) {
            acceptedItem->qosFlowLevelQosParameters = asn::New<ASN_NGAP_QosFlowLevelQosParameters>();
            if (acceptedItem->qosFlowLevelQosParameters) {
                *acceptedItem->qosFlowLevelQosParameters = *qosFlowSetupRequestItem.qosFlowLevelQosParameters;
            } else {
                m_logger->err("Failed to allocate memory for qosFlowLevelQosParameters");
            }
        }

        if (qosFlowSetupRequestItem.e_RAB_ID) {
            acceptedItem->e_RAB_ID = asn::New<ASN_NGAP_E_RAB_ID>();
            if (acceptedItem->e_RAB_ID) {
                *acceptedItem->e_RAB_ID = *qosFlowSetupRequestItem.e_RAB_ID;
            } else {
                m_logger->err("Failed to allocate memory for e_RAB_ID");
            }
        }

        if (qosFlowSetupRequestItem.iE_Extensions) {
            acceptedItem->iE_Extensions = asn::New<ASN_NGAP_ProtocolExtensionContainer>();
            if (acceptedItem->iE_Extensions) {
                *acceptedItem->iE_Extensions = *qosFlowSetupRequestItem.iE_Extensions;
            } else {
                m_logger->err("Failed to allocate memory for iE_Extensions");
            }
        }

        // Add to list
        ASN_SEQUENCE_ADD(&qosFlowAcceptedList->list, acceptedItem);
    }
    // Before encoding
    
    // Logging field values
    std::cout<<"GTP Tunnel Address (hex): ";
    for (size_t i = 0; i < gTPTunnel->transportLayerAddress.size; ++i) {
        printf("%02x ", gTPTunnel->transportLayerAddress.buf[i]);
    }
    printf("\n");

    std::cout<<"GTP TEID (hex): ";
    for (size_t i = 0; i < gTPTunnel->gTP_TEID.size; ++i) {
        printf("%02x ", gTPTunnel->gTP_TEID.buf[i]);
    }
    printf("\n");

    // Check if any fields are null or improperly initialized
    if (!gTPTunnel->transportLayerAddress.buf) {
        std::cout<<"GTP Tunnel Address buffer is null"<<"\n";
    }
    if (!gTPTunnel->gTP_TEID.buf) {
        std::cout<<"GTP TEID buffer is null \n";
    }


    // Assign QosFlowAcceptedList to pathSwitchRequestTransfer
    pathSwitchRequestTransfer->qosFlowAcceptedList = *qosFlowAcceptedList;

    // Encoding PathSwitchRequestTransfer
    asn_encode_to_new_buffer_result_t rval = asn_encode_to_new_buffer(
        nullptr,  // Codec context, use nullptr if not needed
        ATS_ALIGNED_BASIC_PER,  // Transfer syntax
        &asn_DEF_ASN_NGAP_PathSwitchRequestTransfer,  // ASN.1 type descriptor
        pathSwitchRequestTransfer  // Pointer to the structure
    );

    if (rval.buffer == nullptr) {
        // Encoding failed
        std::cerr << "Encoding failed or returned null buffer!" << std::endl;
    } 
    // Encoding succeeded
    // Cast the buffer to the correct type
    uint8_t* encoded_buffer = static_cast<uint8_t*>(rval.buffer);
    size_t encoded_size = rval.result.encoded;  // Use the encoded size from asn_enc_rval_t

    // Initialize OCTET_STRING_t
    octetString.buf = std::move(encoded_buffer);
    octetString.size = std::move(encoded_size);

    // Optionally, log the encoded buffer size
    std::cout << "Encoded PathSwitchRequestTransfer size: " << octetString.size << " bytes" << std::endl;
        // Assign PathSwitchRequestTransfer to item
    item->pathSwitchRequestTransfer = octetString;

    // Add item to the list
    pduList->list.array[0] = item;
    pduList->list.count = 1; 
    return *pduList;
}*/
}


