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

#include <gnb/app/task.hpp>
#include <gnb/nts.hpp>
#include <gnb/sctp/task.hpp>
#include <lib/asn/ngap.hpp>
#include <lib/asn/utils.hpp>

#include <asn/ngap/ASN_NGAP_AMF-UE-NGAP-ID.h>
#include <asn/ngap/ASN_NGAP_InitiatingMessage.h>
#include <asn/ngap/ASN_NGAP_NGAP-PDU.h>
#include <asn/ngap/ASN_NGAP_ProtocolIE-Field.h>
#include <asn/ngap/ASN_NGAP_RAN-UE-NGAP-ID.h>
#include <asn/ngap/ASN_NGAP_SuccessfulOutcome.h>
#include <asn/ngap/ASN_NGAP_UnsuccessfulOutcome.h>
//Urwah
#include <utils/octet_string.hpp>
#include <utils/octet_view.hpp>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceToBeSwitchedDLItem.h>
#include <asn/ngap/ASN_NGAP_PathSwitchRequest.h>
#include <asn/ngap/ASN_NGAP_PathSwitchRequestTransfer.h>
#include "asn/ngap/ASN_NGAP_GTPTunnel.h"
#include "asn/ngap/ASN_NGAP_QosFlowAcceptedItem.h"
#include "asn/ngap/ASN_NGAP_QosFlowSetupRequestItem.h" // Adjust the path as necessary
#include <asn/ngap/ASN_NGAP_UESecurityCapabilities.h>
#include <asn/asn1c/OCTET_STRING.h>


#include <asn/ngap/ASN_NGAP_UserLocationInformation.h>
#include <asn/ngap/ASN_NGAP_UserLocationInformationNR.h>
#include <iostream>

void printSecurityCapability(const nas::IEUeSecurityCapability& cap) {
    std::cout << "IEUeSecurityCapability values:" << std::endl;
    std::cout << "b_5G_EA0: " << cap.b_5G_EA0 << std::endl;
    std::cout << "b_128_5G_EA1: " << cap.b_128_5G_EA1 << std::endl;
    std::cout << "b_128_5G_EA2: " << cap.b_128_5G_EA2 << std::endl;
    std::cout << "b_128_5G_EA3: " << cap.b_128_5G_EA3 << std::endl;
    std::cout << "b_5G_EA4: " << cap.b_5G_EA4 << std::endl;
    std::cout << "b_5G_EA5: " << cap.b_5G_EA5 << std::endl;
    std::cout << "b_5G_EA6: " << cap.b_5G_EA6 << std::endl;
    std::cout << "b_5G_EA7: " << cap.b_5G_EA7 << std::endl;
    std::cout << "b_5G_IA0: " << cap.b_5G_IA0 << std::endl;
    std::cout << "b_128_5G_IA1: " << cap.b_128_5G_IA1 << std::endl;
    std::cout << "b_128_5G_IA2: " << cap.b_128_5G_IA2 << std::endl;
    std::cout << "b_128_5G_IA3: " << cap.b_128_5G_IA3 << std::endl;
    std::cout << "b_5G_IA4: " << cap.b_5G_IA4 << std::endl;
    std::cout << "b_5G_IA5: " << cap.b_5G_IA5 << std::endl;
    std::cout << "b_5G_IA6: " << cap.b_5G_IA6 << std::endl;
    std::cout << "b_5G_IA7: " << cap.b_5G_IA7 << std::endl;
    std::cout << "b_EEA0: " << cap.b_EEA0 << std::endl;
    std::cout << "b_128_EEA1: " << cap.b_128_EEA1 << std::endl;
    std::cout << "b_128_EEA2: " << cap.b_128_EEA2 << std::endl;
    std::cout << "b_128_EEA3: " << cap.b_128_EEA3 << std::endl;
    std::cout << "b_EEA4: " << cap.b_EEA4 << std::endl;
    std::cout << "b_EEA5: " << cap.b_EEA5 << std::endl;
    std::cout << "b_EEA6: " << cap.b_EEA6 << std::endl;
    std::cout << "b_EEA7: " << cap.b_EEA7 << std::endl;
    std::cout << "b_EIA0: " << cap.b_EIA0 << std::endl;
    std::cout << "b_128_EIA1: " << cap.b_128_EIA1 << std::endl;
    std::cout << "b_128_EIA2: " << cap.b_128_EIA2 << std::endl;
    std::cout << "b_128_EIA3: " << cap.b_128_EIA3 << std::endl;
    std::cout << "b_EIA4: " << cap.b_EIA4 << std::endl;
    std::cout << "b_EIA5: " << cap.b_EIA5 << std::endl;
    std::cout << "b_EIA6: " << cap.b_EIA6 << std::endl;
    std::cout << "b_EIA7: " << cap.b_EIA7 << std::endl;
}

static e_ASN_NGAP_Criticality FindCriticalityOfUserIe(ASN_NGAP_NGAP_PDU *pdu, ASN_NGAP_ProtocolIE_ID_t ieId)
{
    auto procedureCode =
        pdu->present == ASN_NGAP_NGAP_PDU_PR_initiatingMessage   ? pdu->choice.initiatingMessage->procedureCode
        : pdu->present == ASN_NGAP_NGAP_PDU_PR_successfulOutcome ? pdu->choice.successfulOutcome->procedureCode
                                                                 : pdu->choice.unsuccessfulOutcome->procedureCode;

    if (ieId == ASN_NGAP_ProtocolIE_ID_id_UserLocationInformation)
    {
        return procedureCode == ASN_NGAP_ProcedureCode_id_InitialUEMessage ? ASN_NGAP_Criticality_reject
                                                                           : ASN_NGAP_Criticality_ignore;
    }

    if (ieId == ASN_NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID || ieId == ASN_NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID)
    {
        if (procedureCode == ASN_NGAP_ProcedureCode_id_RerouteNASRequest)
        {
            return ieId == ASN_NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID ? ASN_NGAP_Criticality_reject
                                                                    : ASN_NGAP_Criticality_ignore;
        }

        if (pdu->present == ASN_NGAP_NGAP_PDU_PR_initiatingMessage)
        {
            if (procedureCode == ASN_NGAP_ProcedureCode_id_UEContextReleaseRequest ||
                procedureCode == ASN_NGAP_ProcedureCode_id_HandoverPreparation)
                return ASN_NGAP_Criticality_reject;
        }

        if (procedureCode == ASN_NGAP_ProcedureCode_id_PDUSessionResourceNotify ||
            procedureCode == ASN_NGAP_ProcedureCode_id_PDUSessionResourceModifyIndication ||
            procedureCode == ASN_NGAP_ProcedureCode_id_RRCInactiveTransitionReport ||
            procedureCode == ASN_NGAP_ProcedureCode_id_HandoverNotification ||
            procedureCode == ASN_NGAP_ProcedureCode_id_PathSwitchRequest ||
            procedureCode == ASN_NGAP_ProcedureCode_id_HandoverCancel ||
            procedureCode == ASN_NGAP_ProcedureCode_id_UplinkRANStatusTransfer ||
            procedureCode == ASN_NGAP_ProcedureCode_id_InitialUEMessage ||
            procedureCode == ASN_NGAP_ProcedureCode_id_DownlinkNASTransport ||
            procedureCode == ASN_NGAP_ProcedureCode_id_UplinkNASTransport ||
            procedureCode == ASN_NGAP_ProcedureCode_id_NASNonDeliveryIndication ||
            procedureCode == ASN_NGAP_ProcedureCode_id_UplinkUEAssociatedNRPPaTransport ||
            procedureCode == ASN_NGAP_ProcedureCode_id_UplinkNonUEAssociatedNRPPaTransport ||
            procedureCode == ASN_NGAP_ProcedureCode_id_CellTrafficTrace ||
            procedureCode == ASN_NGAP_ProcedureCode_id_TraceStart ||
            procedureCode == ASN_NGAP_ProcedureCode_id_DeactivateTrace ||
            procedureCode == ASN_NGAP_ProcedureCode_id_TraceFailureIndication ||
            procedureCode == ASN_NGAP_ProcedureCode_id_LocationReport ||
            procedureCode == ASN_NGAP_ProcedureCode_id_LocationReportingControl ||
            procedureCode == ASN_NGAP_ProcedureCode_id_LocationReportingFailureIndication ||
            procedureCode == ASN_NGAP_ProcedureCode_id_UERadioCapabilityInfoIndication)
            return ASN_NGAP_Criticality_reject;
    }

    return ASN_NGAP_Criticality_ignore;
}

namespace nr::gnb
{

void NgapTask::sendNgapNonUe(int associatedAmf, ASN_NGAP_NGAP_PDU *pdu)
{
    auto *amf = findAmfContext(associatedAmf);
    if (amf == nullptr)
    {
        asn::Free(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
        return;
    }

    char errorBuffer[1024];
    size_t len;

    if (asn_check_constraints(&asn_DEF_ASN_NGAP_NGAP_PDU, pdu, errorBuffer, &len) != 0)
    {
        m_logger->err("NGAP PDU ASN constraint validation failed");
        asn::Free(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
        return;
    }

    ssize_t encoded;
    uint8_t *buffer;
    if (!ngap_encode::Encode(asn_DEF_ASN_NGAP_NGAP_PDU, pdu, encoded, buffer))
        m_logger->err("NGAP APER encoding failed");
    else
    {
        auto msg = std::make_unique<NmGnbSctp>(NmGnbSctp::SEND_MESSAGE);
        msg->clientId = amf->ctxId;
        msg->stream = 0;
        msg->buffer = UniqueBuffer{buffer, static_cast<size_t>(encoded)};
        m_base->sctpTask->push(std::move(msg));

        if (m_base->nodeListener)
        {
            std::string xer = ngap_encode::EncodeXer(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
            if (xer.length() > 0)
            {
                m_base->nodeListener->onSend(app::NodeType::GNB, m_base->config->name, app::NodeType::AMF, amf->amfName,
                                             app::ConnectionType::NGAP, xer);
            }
        }
    }

    asn::Free(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
}

void NgapTask::sendNgapUeAssociatedPathSwitchReq(int ueId, ASN_NGAP_NGAP_PDU *pdu, const PduSessionResource& pduSessionResource,
                const nas::IEUeSecurityCapability ueSecurityCapability)
{
    //auto *pduList = reinterpret_cast<ASN_NGAP_PDUSessionResourceToBeSwitchedDLList *>(mem);
    auto pduList = std::make_unique<ASN_NGAP_PDUSessionResourceToBeSwitchedDLList>();

    pduList->list.count = 0;
    pduList->list.size = 1; // Assuming only one PDU session resource for now
    pduList->list.array = (ASN_NGAP_PDUSessionResourceToBeSwitchedDLItem **)calloc(pduList->list.size, sizeof(ASN_NGAP_PDUSessionResourceToBeSwitchedDLItem *));
    
    if (pduList->list.array == nullptr)
    {
        m_logger->err("Failed to allocate memory for PDUSessionResourceToBeSwitchedDLList");
        return;
    }
    auto *item = asn::New<ASN_NGAP_PDUSessionResourceToBeSwitchedDLItem>();
    item->pDUSessionID = pduSessionResource.psi;
    OCTET_STRING_t octetString;

    // Initialize PathSwitchRequestTransfer and assign values
    auto *pathSwitchRequestTransfer = asn::New<ASN_NGAP_PathSwitchRequestTransfer>();

    // Initialize GTP Tunnel
    pathSwitchRequestTransfer->dL_NGU_UP_TNLInformation.present = ASN_NGAP_UPTransportLayerInformation_PR_gTPTunnel;
    pathSwitchRequestTransfer->dL_NGU_UP_TNLInformation.choice.gTPTunnel = asn::New<ASN_NGAP_GTPTunnel>();

    auto* gTPTunnel = pathSwitchRequestTransfer->dL_NGU_UP_TNLInformation.choice.gTPTunnel;
    const auto& address = pduSessionResource.downTunnel.address;
    gTPTunnel->transportLayerAddress.size = address.length();  // Use the correct method for size
    gTPTunnel->transportLayerAddress.buf = new uint8_t[gTPTunnel->transportLayerAddress.size];
    std::memcpy(gTPTunnel->transportLayerAddress.buf, address.data(), gTPTunnel->transportLayerAddress.size);  // Use the correct method for buffer

    gTPTunnel->gTP_TEID.size = sizeof(uint32_t);
    gTPTunnel->gTP_TEID.buf = new uint8_t[gTPTunnel->gTP_TEID.size];
    std::memcpy(gTPTunnel->gTP_TEID.buf, &pduSessionResource.downTunnel.teid, sizeof(uint32_t));
    std::cout<<"res->m_pduSession->upTunnel.teid: "<<pduSessionResource.downTunnel.teid<<std::endl;

    if (pduSessionResource.dataForwardingNotPossible)
    {
        pathSwitchRequestTransfer->userPlaneSecurityInformation = nullptr;
    }
    // Create and initialize QosFlowAcceptedList
    auto* qosFlowAcceptedList = asn::New<ASN_NGAP_QosFlowAcceptedList>();
    if (!qosFlowAcceptedList) {
        m_logger->err("Failed to allocate memory for QosFlowAcceptedList");
        return;
    }

    qosFlowAcceptedList->list.count = 0;
    qosFlowAcceptedList->list.count = pduSessionResource.qosFlows->list.count;
    std::cout<<"pduSessionResource.qosFlows->list.count = "<<pduSessionResource.qosFlows->list.count<<std::endl;                qosFlowAcceptedList->list.array = (ASN_NGAP_QosFlowAcceptedItem **)calloc(qosFlowAcceptedList->list.count, sizeof(ASN_NGAP_QosFlowAcceptedItem *));
    std::cout<<"static_cast<int>(qosList.array[iQos]->qosFlowIdentifier): "<<static_cast<int>(pduSessionResource.qosFlows->list.array[0]->qosFlowIdentifier)<<std::endl;
    if (qosFlowAcceptedList->list.array == nullptr) {
        m_logger->err("Failed to allocate memory for QosFlowAcceptedList array");
        return;
    }

    // Add QoS Flow Accepted Items
    for (int i = 0; i < pduSessionResource.qosFlows->list.count; ++i) {
        const auto& qosFlowSetupRequestItem = *pduSessionResource.qosFlows->list.array[i];
        auto* acceptedItem = asn::New<ASN_NGAP_QosFlowAcceptedItem>();
        if (!acceptedItem) {
            m_logger->err("Failed to allocate memory for QosFlowAcceptedItem");
            continue;
        }

        // Copy data
        acceptedItem->qosFlowIdentifier = qosFlowSetupRequestItem.qosFlowIdentifier;
        m_logger->info("QoS Flow Accepted Item {} - QoS Flow Identifier: {}",
                        i, acceptedItem->qosFlowIdentifier);
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
        }*/

        // Add to list
        ASN_SEQUENCE_ADD(&qosFlowAcceptedList->list, acceptedItem);
    }
    // Before encoding
    m_logger->info("PathSwitchRequestTransfer Debug:");
    m_logger->info("DL NGU UP TNL Information - Address Size: {}, TEID Size: {}",
                gTPTunnel->transportLayerAddress.size, gTPTunnel->gTP_TEID.size);

    // Logging field values
    m_logger->info("GTP Tunnel Address (hex):");
    for (size_t i = 0; i < gTPTunnel->transportLayerAddress.size; ++i) {
        printf("%02x ", gTPTunnel->transportLayerAddress.buf[i]);
    }
    printf("\n");

    m_logger->info("GTP TEID (hex):");
    for (size_t i = 0; i < gTPTunnel->gTP_TEID.size; ++i) {
        printf("%02x ", gTPTunnel->gTP_TEID.buf[i]);
    }
    printf("\n");

    // Check if any fields are null or improperly initialized
    if (!gTPTunnel->transportLayerAddress.buf) {
        m_logger->err("GTP Tunnel Address buffer is null");
    }
    if (!gTPTunnel->gTP_TEID.buf) {
        m_logger->err("GTP TEID buffer is null");
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
    } else {
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

    }



    // Find UE and AMF contexts
    auto *ue = findUeContext(ueId);
    if (ue == nullptr)
    {
        asn::Free(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
        return;
    }

    auto *amf = findAmfContext(ue->associatedAmfId);
    if (amf == nullptr)
    {
        asn::Free(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
        return;
    }

    // Insert UE-related information elements
    {
        // AMF UE NGAP ID
       /* if (ue->amfUeNgapId > 0)
        {
            asn::ngap::AddProtocolIeIfUsable(
                *pdu, asn_DEF_ASN_NGAP_AMF_UE_NGAP_ID, ASN_NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID,
                FindCriticalityOfUserIe(pdu, ASN_NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID),
                [ue](void *mem) {
                    auto &id = *reinterpret_cast<ASN_NGAP_AMF_UE_NGAP_ID_t *>(mem);
                    asn::SetSigned64(ue->amfUeNgapId, id);
                });
        }

        // RAN UE NGAP ID
        asn::ngap::AddProtocolIeIfUsable(
            *pdu, asn_DEF_ASN_NGAP_RAN_UE_NGAP_ID, ASN_NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID,
            FindCriticalityOfUserIe(pdu, ASN_NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID),
            [ue](void *mem) { *reinterpret_cast<ASN_NGAP_RAN_UE_NGAP_ID_t *>(mem) = ue->ranUeNgapId; });

        // User Location Information
        asn::ngap::AddProtocolIeIfUsable(
            *pdu, asn_DEF_ASN_NGAP_UserLocationInformation, ASN_NGAP_ProtocolIE_ID_id_UserLocationInformation,
            FindCriticalityOfUserIe(pdu, ASN_NGAP_ProtocolIE_ID_id_UserLocationInformation), [this](void *mem) {
                auto *loc = reinterpret_cast<ASN_NGAP_UserLocationInformation *>(mem);
                loc->present = ASN_NGAP_UserLocationInformation_PR_userLocationInformationNR;
                loc->choice.userLocationInformationNR = asn::New<ASN_NGAP_UserLocationInformationNR>();

                auto &nr = loc->choice.userLocationInformationNR;
                nr->timeStamp = asn::New<ASN_NGAP_TimeStamp_t>();

                ngap_utils::ToPlmnAsn_Ref(m_base->config->plmn, nr->nR_CGI.pLMNIdentity);
                asn::SetBitStringLong<36>(m_base->config->nci, nr->nR_CGI.nRCellIdentity);
                ngap_utils::ToPlmnAsn_Ref(m_base->config->plmn, nr->tAI.pLMNIdentity);
                asn::SetOctetString3(nr->tAI.tAC, octet3{m_base->config->tac});
                asn::SetOctetString4(*nr->timeStamp, octet4{utils::CurrentTimeStamp().seconds32()});
            });*/
        // Create a lambda that captures by value
        auto lambda = [this, &pduList](void *mem) {
            auto *list = reinterpret_cast<ASN_NGAP_PDUSessionResourceToBeSwitchedDLList *>(mem);
            *list = *pduList; // Copy the list into the PDU
        };
        // PDUSessionResourceToBeSwitchedDLList
        asn::ngap::AddProtocolIeIfUsable(
            *pdu, asn_DEF_ASN_NGAP_PDUSessionResourceToBeSwitchedDLList, 
            ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceToBeSwitchedDLList,
            FindCriticalityOfUserIe(pdu, ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceToBeSwitchedDLList), lambda
        );
        //printSecurityCapability(ueSecurityCapability);
        // UE Security Capabilities
        asn::ngap::AddProtocolIeIfUsable(
            *pdu, asn_DEF_ASN_NGAP_UESecurityCapabilities, ASN_NGAP_ProtocolIE_ID_id_UESecurityCapabilities,
            FindCriticalityOfUserIe(pdu, ASN_NGAP_ProtocolIE_ID_id_UESecurityCapabilities), 
            [this, &ueSecurityCapability](void *mem) {
                auto &secCap = *reinterpret_cast<ASN_NGAP_UESecurityCapabilities_t *>(mem);

                // Prepare the stream for encoded data
                OctetString stream;

                // Encode the UE Security Capability into the stream
                nas::IEUeSecurityCapability::Encode(ueSecurityCapability, stream);
                // Assign the encoded stream to the ASN.1 structure for UESecurityCapabilities
                // Encryption algorithms
                secCap.nRencryptionAlgorithms.buf = (uint8_t *)stream.data();
                secCap.nRencryptionAlgorithms.size = 2; // For the first two octets (encryption and integrity)
                secCap.nRencryptionAlgorithms.bits_unused = 0;

                // Integrity protection algorithms
                secCap.nRintegrityProtectionAlgorithms.buf = (uint8_t *)(stream.data() + 2); // Next two octets
                secCap.nRintegrityProtectionAlgorithms.size = 2; // For the integrity algorithms
                secCap.nRintegrityProtectionAlgorithms.bits_unused = 0;
                //asn::SetOctetString4();
            });

    }

     /* Encode and send the PDU */

    char errorBuffer[1024];
    size_t len;

    if (asn_check_constraints(&asn_DEF_ASN_NGAP_NGAP_PDU, pdu, errorBuffer, &len) != 0)
    {
        m_logger->err("NGAP PDU ASN constraint validation failed");
        asn::Free(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
        return;
    }

    ssize_t encoded;
    uint8_t *buffer;
    if (!ngap_encode::Encode(asn_DEF_ASN_NGAP_NGAP_PDU, pdu, encoded, buffer))
        m_logger->err("NGAP APER encoding failed");
    else
    {
        auto msg = std::make_unique<NmGnbSctp>(NmGnbSctp::SEND_MESSAGE);
        msg->clientId = amf->ctxId;
        msg->stream = ue->uplinkStream;
        msg->buffer = UniqueBuffer{buffer, static_cast<size_t>(encoded)};
        m_base->sctpTask->push(std::move(msg));
        if (m_base->nodeListener)
        {
            std::string xer = ngap_encode::EncodeXer(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
            if (xer.length() > 0)
            {
                m_base->nodeListener->onSend(app::NodeType::GNB, m_base->config->name, app::NodeType::AMF, amf->amfName,
                                             app::ConnectionType::NGAP, xer);
            }
        }
    }

    asn::Free(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
}



void NgapTask::sendNgapUeAssociated(int ueId, ASN_NGAP_NGAP_PDU *pdu)
{
    /* Find UE and AMF contexts */
    auto *ue = findUeContext(ueId);
    if (ue == nullptr)
    {
        asn::Free(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
        return;
    }

    auto *amf = findAmfContext(ue->associatedAmfId);
    if (amf == nullptr)
    {
        asn::Free(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
        return;
    }

    /* Insert UE-related information elements */
    {
        if (ue->amfUeNgapId > 0)
        {
            asn::ngap::AddProtocolIeIfUsable(
                *pdu, asn_DEF_ASN_NGAP_AMF_UE_NGAP_ID, ASN_NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID,
                FindCriticalityOfUserIe(pdu, ASN_NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID), [ue](void *mem) {
                    auto &id = *reinterpret_cast<ASN_NGAP_AMF_UE_NGAP_ID_t *>(mem);
                    asn::SetSigned64(ue->amfUeNgapId, id);
                });
        }
        asn::ngap::AddProtocolIeIfUsable(
            *pdu, asn_DEF_ASN_NGAP_RAN_UE_NGAP_ID, ASN_NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID,
            FindCriticalityOfUserIe(pdu, ASN_NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID),
            [ue](void *mem) { *reinterpret_cast<ASN_NGAP_RAN_UE_NGAP_ID_t *>(mem) = ue->ranUeNgapId; });

        asn::ngap::AddProtocolIeIfUsable(
            *pdu, asn_DEF_ASN_NGAP_UserLocationInformation, ASN_NGAP_ProtocolIE_ID_id_UserLocationInformation,
            FindCriticalityOfUserIe(pdu, ASN_NGAP_ProtocolIE_ID_id_UserLocationInformation), [this](void *mem) {
                auto *loc = reinterpret_cast<ASN_NGAP_UserLocationInformation *>(mem);
                loc->present = ASN_NGAP_UserLocationInformation_PR_userLocationInformationNR;
                loc->choice.userLocationInformationNR = asn::New<ASN_NGAP_UserLocationInformationNR>();

                auto &nr = loc->choice.userLocationInformationNR;
                nr->timeStamp = asn::New<ASN_NGAP_TimeStamp_t>();

                ngap_utils::ToPlmnAsn_Ref(m_base->config->plmn, nr->nR_CGI.pLMNIdentity);
                asn::SetBitStringLong<36>(m_base->config->nci, nr->nR_CGI.nRCellIdentity);
                ngap_utils::ToPlmnAsn_Ref(m_base->config->plmn, nr->tAI.pLMNIdentity);
                asn::SetOctetString3(nr->tAI.tAC, octet3{m_base->config->tac});
                asn::SetOctetString4(*nr->timeStamp, octet4{utils::CurrentTimeStamp().seconds32()});
            });
    }

    /* Encode and send the PDU */

    char errorBuffer[1024];
    size_t len;

    if (asn_check_constraints(&asn_DEF_ASN_NGAP_NGAP_PDU, pdu, errorBuffer, &len) != 0)
    {
        m_logger->err("NGAP PDU ASN constraint validation failed");
        asn::Free(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
        return;
    }

    ssize_t encoded;
    uint8_t *buffer;
    if (!ngap_encode::Encode(asn_DEF_ASN_NGAP_NGAP_PDU, pdu, encoded, buffer))
        m_logger->err("NGAP APER encoding failed");
    else
    {
        auto msg = std::make_unique<NmGnbSctp>(NmGnbSctp::SEND_MESSAGE);
        msg->clientId = amf->ctxId;
        msg->stream = ue->uplinkStream;
        msg->buffer = UniqueBuffer{buffer, static_cast<size_t>(encoded)};
        m_base->sctpTask->push(std::move(msg));
        if (m_base->nodeListener)
        {
            std::string xer = ngap_encode::EncodeXer(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
            if (xer.length() > 0)
            {
                m_base->nodeListener->onSend(app::NodeType::GNB, m_base->config->name, app::NodeType::AMF, amf->amfName,
                                             app::ConnectionType::NGAP, xer);
            }
        }
    }

    asn::Free(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
}

void NgapTask::handleSctpMessage(int amfId, uint16_t stream, const UniqueBuffer &buffer)
{
    auto *amf = findAmfContext(amfId);
    if (amf == nullptr)
        return;

    auto *pdu = ngap_encode::Decode<ASN_NGAP_NGAP_PDU>(asn_DEF_ASN_NGAP_NGAP_PDU, buffer.data(), buffer.size());
    if (pdu == nullptr)
    {
        m_logger->err("APER decoding failed for SCTP message");
        asn::Free(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
        sendErrorIndication(amfId, NgapCause::Protocol_transfer_syntax_error);
        return;
    }

    if (m_base->nodeListener)
    {
        std::string xer = ngap_encode::EncodeXer(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
        if (xer.length() > 0)
        {
            m_base->nodeListener->onReceive(app::NodeType::GNB, m_base->config->name, app::NodeType::AMF, amf->amfName,
                                            app::ConnectionType::NGAP, xer);
        }
    }

    if (!handleSctpStreamId(amf->ctxId, stream, *pdu))
    {
        asn::Free(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
        return;
    }

    if (pdu->present == ASN_NGAP_NGAP_PDU_PR_initiatingMessage)
    {
        auto value = pdu->choice.initiatingMessage->value;
        switch (value.present)
        {
        case ASN_NGAP_InitiatingMessage__value_PR_ErrorIndication:
            receiveErrorIndication(amf->ctxId, &value.choice.ErrorIndication);
            break;
        case ASN_NGAP_InitiatingMessage__value_PR_InitialContextSetupRequest:
            receiveInitialContextSetup(amf->ctxId, &value.choice.InitialContextSetupRequest);
            break;
        case ASN_NGAP_InitiatingMessage__value_PR_RerouteNASRequest:
            receiveRerouteNasRequest(amf->ctxId, &value.choice.RerouteNASRequest);
            break;
        case ASN_NGAP_InitiatingMessage__value_PR_UEContextReleaseCommand:
            receiveContextRelease(amf->ctxId, &value.choice.UEContextReleaseCommand);
            break;
        case ASN_NGAP_InitiatingMessage__value_PR_UEContextModificationRequest:
            receiveContextModification(amf->ctxId, &value.choice.UEContextModificationRequest);
            break;
        case ASN_NGAP_InitiatingMessage__value_PR_PDUSessionResourceSetupRequest:
            receiveSessionResourceSetupRequest(amf->ctxId, &value.choice.PDUSessionResourceSetupRequest);
            break;
        case ASN_NGAP_InitiatingMessage__value_PR_DownlinkNASTransport:
            receiveDownlinkNasTransport(amf->ctxId, &value.choice.DownlinkNASTransport);
            break;
        case ASN_NGAP_InitiatingMessage__value_PR_AMFConfigurationUpdate:
            receiveAmfConfigurationUpdate(amf->ctxId, &value.choice.AMFConfigurationUpdate);
            break;
        case ASN_NGAP_InitiatingMessage__value_PR_OverloadStart:
            receiveOverloadStart(amf->ctxId, &value.choice.OverloadStart);
            break;
        case ASN_NGAP_InitiatingMessage__value_PR_OverloadStop:
            receiveOverloadStop(amf->ctxId, &value.choice.OverloadStop);
            break;
        case ASN_NGAP_InitiatingMessage__value_PR_PDUSessionResourceReleaseCommand:
            receiveSessionResourceReleaseCommand(amf->ctxId, &value.choice.PDUSessionResourceReleaseCommand);
            break;
        case ASN_NGAP_InitiatingMessage__value_PR_Paging:
            receivePaging(amf->ctxId, &value.choice.Paging);
            break;
        default:
            m_logger->err("Unhandled NGAP initiating-message received (%d)", value.present);
            break;
        }
    }
    else if (pdu->present == ASN_NGAP_NGAP_PDU_PR_successfulOutcome)
    {
        auto value = pdu->choice.successfulOutcome->value;
        switch (value.present)
        {
        case ASN_NGAP_SuccessfulOutcome__value_PR_NGSetupResponse:
            receiveNgSetupResponse(amf->ctxId, &value.choice.NGSetupResponse);
            break;
        default:
            m_logger->err("Unhandled NGAP successful-outcome received (%d)", value.present);
            break;
        }
    }
    else if (pdu->present == ASN_NGAP_NGAP_PDU_PR_unsuccessfulOutcome)
    {
        auto value = pdu->choice.unsuccessfulOutcome->value;
        switch (value.present)
        {
        case ASN_NGAP_UnsuccessfulOutcome__value_PR_NGSetupFailure:
            receiveNgSetupFailure(amf->ctxId, &value.choice.NGSetupFailure);
            break;
        default:
            m_logger->err("Unhandled NGAP unsuccessful-outcome received (%d)", value.present);
            break;
        }
    }
    else
    {
        m_logger->warn("Empty NGAP PDU ignored");
    }

    asn::Free(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
}

bool NgapTask::handleSctpStreamId(int amfId, int stream, const ASN_NGAP_NGAP_PDU &pdu)
{
    if (m_base->config->ignoreStreamIds)
        return true;

    auto *ptr =
        asn::ngap::FindProtocolIeInPdu(pdu, asn_DEF_ASN_NGAP_UE_NGAP_IDs, ASN_NGAP_ProtocolIE_ID_id_UE_NGAP_IDs);
    if (ptr != nullptr)
    {
        if (stream == 0)
        {
            m_logger->err("Received stream number == 0 in UE-associated signalling");
            sendErrorIndication(amfId, NgapCause::Protocol_unspecified);
            return false;
        }

        auto &ids = *reinterpret_cast<ASN_NGAP_UE_NGAP_IDs *>(ptr);
        auto *ue = findUeByNgapIdPair(amfId, ngap_utils::FindNgapIdPairFromAsnNgapIds(ids));
        if (ue == nullptr)
            return false;

        if (ue->downlinkStream == 0)
            ue->downlinkStream = stream;
        else if (ue->downlinkStream != stream)
        {
            m_logger->err("received stream number is inconsistent. received %d, expected :%d", stream,
                          ue->downlinkStream);
            sendErrorIndication(amfId, NgapCause::Protocol_unspecified);
            return false;
        }
    }
    else
    {
        ptr = asn::ngap::FindProtocolIeInPdu(pdu, asn_DEF_ASN_NGAP_RAN_UE_NGAP_ID,
                                             ASN_NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID);
        if (ptr != nullptr)
        {
            if (stream == 0)
            {
                m_logger->err("Received stream number == 0 in UE-associated signalling");
                sendErrorIndication(amfId, NgapCause::Protocol_unspecified);
                return false;
            }

            auto id = static_cast<int64_t>(*reinterpret_cast<ASN_NGAP_RAN_UE_NGAP_ID_t *>(ptr));
            auto *ue = findUeByRanId(id);
            if (ue == nullptr)
                return false;

            if (ue->downlinkStream == 0)
                ue->downlinkStream = stream;
            else if (ue->downlinkStream != stream)
            {
                m_logger->err("received stream number is inconsistent. received %d, expected :%d", stream,
                              ue->downlinkStream);
                sendErrorIndication(amfId, NgapCause::Protocol_unspecified);
                return false;
            }
        }
        else
        {
            if (stream != 0)
            {
                m_logger->err("Received stream number != 0 in non-UE-associated signalling");
                sendErrorIndication(amfId, NgapCause::Protocol_unspecified);
                return false;
            }
        }
    }

    return true;
}

} // namespace nr::gnb
