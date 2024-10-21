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

static e_ASN_NGAP_Criticality FindCriticalityOfUserIe(ASN_NGAP_NGAP_PDU *pdu, ASN_NGAP_ProtocolIE_ID_t ieId)
{
    auto procedureCode =
        pdu->present == ASN_NGAP_NGAP_PDU_PR_initiatingMessage   ? pdu->choice.initiatingMessage->procedureCode
        : pdu->present == ASN_NGAP_NGAP_PDU_PR_successfulOutcome ? pdu->choice.successfulOutcome->procedureCode
                                                                 : pdu->choice.unsuccessfulOutcome->procedureCode;

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
    // Create PDUSessionResourceToBeSwitchedDLList
    auto pduList = std::make_unique<ASN_NGAP_PDUSessionResourceToBeSwitchedDLList>();
    pduList->list.size = 1;  // Assuming only one PDU session resource for now
    pduList->list.count = 0;
    pduList->list.array = new ASN_NGAP_PDUSessionResourceToBeSwitchedDLItem*[pduList->list.size];
    if (!pduList->list.array) {
        m_logger->err("Failed to allocate memory for PDUSessionResourceToBeSwitchedDLList");
        return;
    }

    std::cout<<"1 \n";
    if (!pduList->list.array) {
        m_logger->err("Failed to allocate memory for PDUSessionResourceToBeSwitchedDLList");
        return;
    }

    auto *item = asn::New<ASN_NGAP_PDUSessionResourceToBeSwitchedDLItem>();
    if (!item) {
        m_logger->err("Failed to allocate memory for PDUSessionResourceToBeSwitchedDLItem");
        return;
    }
    std::cout<<"2 \n";
    item->pDUSessionID = pduSessionResource.psi;

    // Initialize PathSwitchRequestTransfer
    auto *pathSwitchRequestTransfer = asn::New<ASN_NGAP_PathSwitchRequestTransfer>();
    if (!pathSwitchRequestTransfer) {
        m_logger->err("Failed to allocate memory for PathSwitchRequestTransfer");
        return;
    }
    std::cout<<"3 \n";
    pathSwitchRequestTransfer->dL_NGU_UP_TNLInformation.present = ASN_NGAP_UPTransportLayerInformation_PR_gTPTunnel;
    pathSwitchRequestTransfer->dL_NGU_UP_TNLInformation.choice.gTPTunnel = asn::New<ASN_NGAP_GTPTunnel>();
    // Access the GTP Tunnel directly from pathSwitchRequestTransfer
    auto* gTPTunnel = pathSwitchRequestTransfer->dL_NGU_UP_TNLInformation.choice.gTPTunnel;

    if (!gTPTunnel) {
        m_logger->err("Failed to allocate memory for GTPTunnel inside PathSwitchRequestTransfer");
        return;
    }

    // Set the transport layer address
    const auto &address = pduSessionResource.downTunnel.address;
    if (address.length() == 0) {
        m_logger->err("Invalid address length for GTP Tunnel");
        return;
    }

    asn::SetBitString(gTPTunnel->transportLayerAddress, address);
    // Logging transport layer address
    // Log the transport layer address, treating it as a sequence of bytes
    std::cout << "Transport Layer Address (interpreted as bytes):";
    for (size_t i = 0; i < gTPTunnel->transportLayerAddress.size; ++i) {
        std::cout << static_cast<int>(gTPTunnel->transportLayerAddress.buf[i]) << " ";
    }
    std::cout << std::endl;

    asn::SetOctetString4(gTPTunnel->gTP_TEID, (octet4)pduSessionResource.downTunnel.teid);
    // Log the TEID for debugging
    std::cout << "GTP TEID: " << pduSessionResource.downTunnel.teid << std::endl;
    std::cout<<"5 \n";
    
    // Access the QosFlowAcceptedList directly from pathSwitchRequestTransfer
    ASN_NGAP_QosFlowAcceptedList &qosFlowAcceptedList = pathSwitchRequestTransfer->qosFlowAcceptedList;

    // Ensure QoS flow list count is valid
    if (pduSessionResource.qosFlows->list.count == 0) {
        m_logger->warn("No QoS flows available to be accepted");
        return;
    }

    // Set the count and allocate memory for the list
    qosFlowAcceptedList.list.count = pduSessionResource.qosFlows->list.count;
    qosFlowAcceptedList.list.size = qosFlowAcceptedList.list.count;
    qosFlowAcceptedList.list.array = (ASN_NGAP_QosFlowAcceptedItem **)calloc(
        qosFlowAcceptedList.list.size, sizeof(ASN_NGAP_QosFlowAcceptedItem *)
    );

    if (qosFlowAcceptedList.list.array == nullptr) {
        m_logger->err("Failed to allocate memory for QosFlowAcceptedList array");
        return;
    }

    std::cout << "QoS Flow Accepted List count: " << qosFlowAcceptedList.list.count << std::endl;

    // Add QoS Flow Accepted Items
    for (int i = 0; i < pduSessionResource.qosFlows->list.count; ++i) {
        // Retrieve the QoS Flow Setup Request Item from the PDU session resource
        const auto &qosFlowSetupRequestItem = *pduSessionResource.qosFlows->list.array[i];

        // Allocate memory for an ASN_NGAP_QosFlowAcceptedItem
        auto *acceptedItem = asn::New<ASN_NGAP_QosFlowAcceptedItem>();
        if (!acceptedItem) {
            m_logger->err("Failed to allocate memory for QosFlowAcceptedItem");
            std::cerr << "Failed to allocate memory for QoS Flow Accepted Item at index " << i << std::endl;
            return;
        }

        // Copy QoS Flow Identifier
        acceptedItem->qosFlowIdentifier = qosFlowSetupRequestItem.qosFlowIdentifier;

        std::cout << "Adding QoS Flow Accepted Item at index " << i 
                << " with QoS Flow Identifier: " << static_cast<int>(acceptedItem->qosFlowIdentifier) << std::endl;

        // Add to list using memcpy
        qosFlowAcceptedList.list.array[i] = static_cast<ASN_NGAP_QosFlowAcceptedItem *>(malloc(sizeof(ASN_NGAP_QosFlowAcceptedItem)));
        if (!qosFlowAcceptedList.list.array[i]) {
            m_logger->err("Failed to allocate memory for QosFlowAcceptedItem in the list");
            std::cerr << "Failed to allocate memory for QoS Flow Accepted Item in list at index " << i << std::endl;
            return;
        }
        *qosFlowAcceptedList.list.array[i] = *acceptedItem;
        //std::memcpy(qosFlowAcceptedList.list.array[i], acceptedItem, sizeof(ASN_NGAP_QosFlowAcceptedItem));
        //ASN_SEQUENCE_ADD(&qosFlowAcceptedList.list, acceptedItem);

        // Verify the item was added correctly
        if (qosFlowAcceptedList.list.array[i] == nullptr) {
            std::cerr << "Added null QoS Flow Accepted Item at index " << i << std::endl;
            return;
        } else {
            std::cout << "Successfully added QoS Flow Accepted Item at index " << i << std::endl;
        }

        // Free the temporary acceptedItem
        free(acceptedItem);
    }



    // Check if there are any QoS flows in the list
    if (qosFlowAcceptedList.list.count > 0) {
        std::cout << "Final QoS Flow Accepted List in pathSwitchRequestTransfer:" << std::endl;
        
        // Loop through each QoS Flow Accepted Item in the list
        for (int i = 0; i < qosFlowAcceptedList.list.count; ++i) {
            ASN_NGAP_QosFlowAcceptedItem* acceptedItem = qosFlowAcceptedList.list.array[i];
            if (acceptedItem) {
                // Print the QoS Flow Identifier
                std::cout << "QoS Flow Accepted Item " << i << " - QoS Flow Identifier: "
                        << static_cast<int>(qosFlowAcceptedList.list.array[i]->qosFlowIdentifier) << std::endl;
            } else {
                std::cerr << "Error: Null QoS Flow Accepted Item at index " << i << std::endl;
            }
        }
    } else {
        std::cout << "No QoS Flow Accepted Items found in pathSwitchRequestTransfer" << std::endl;
    }


    std::cout << "QoS Flow Accepted List successfully populated." << std::endl;

    char error_buffer[128]; // Buffer to store error message
    size_t error_buffer_size = sizeof(error_buffer);

    int constraint_check = asn_check_constraints(
        &asn_DEF_ASN_NGAP_PathSwitchRequestTransfer,
        pathSwitchRequestTransfer,
        error_buffer,
        &error_buffer_size
    );

    if (constraint_check != 0) {
        std::cerr << "Constraint violation during encoding: " << error_buffer << std::endl;
        return;
    }

    ssize_t encoded_length;
    uint8_t* pathSwitchRequestTransfer_buffer = nullptr;
    if (!ngap_encode::Encode(asn_DEF_ASN_NGAP_PathSwitchRequestTransfer, pathSwitchRequestTransfer, encoded_length, pathSwitchRequestTransfer_buffer)) {
        m_logger->err("Failed to encode PathSwitchRequestTransfer");
        return;
    }
    asn::SetOctetString(item->pathSwitchRequestTransfer, OctetString::FromArray(pathSwitchRequestTransfer_buffer, encoded_length));
    std::cout << "Encoded octetString.buf (hex):";

    std::cout << "Encoded OCTET_STRING (hex):";
    for (size_t i = 0; i < item->pathSwitchRequestTransfer.size; ++i) {
        std::cout << std::hex << static_cast<int>(item->pathSwitchRequestTransfer.buf[i]) << " ";
    }
    std::cout << std::dec << std::endl;
    free(pathSwitchRequestTransfer);


    pduList->list.array[0] = item;
    pduList->list.count = 1;

    std::cout << "Added PDUSessionResourceToBeSwitchedDLItem to list" << std::endl;




    // Find UE and AMF contexts
    auto *ue = findUeContext(ueId);
    if (ue == nullptr)
    {
        std::cout << "UE context not found, freeing PDU" << std::endl;
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
        asn::ngap::AddProtocolIeIfUsable(
            *pdu, asn_DEF_ASN_NGAP_RAN_UE_NGAP_ID, ASN_NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID,
            FindCriticalityOfUserIe(pdu, ASN_NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID),
            [ue](void *mem) { *reinterpret_cast<ASN_NGAP_RAN_UE_NGAP_ID_t *>(mem) = ue->ranUeNgapId; });
        std::cout<<"ue->ranUeNgapId: "<<ue->ranUeNgapId<<std::endl;
        // AMF UE NGAP ID
        if (ue->amfUeNgapId > 0)
        {
            asn::ngap::AddProtocolIeIfUsable(
                *pdu, asn_DEF_ASN_NGAP_AMF_UE_NGAP_ID, ASN_NGAP_ProtocolIE_ID_id_SourceAMF_UE_NGAP_ID,
                FindCriticalityOfUserIe(pdu, ASN_NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID), [ue](void *mem) {
                    auto &id = *reinterpret_cast<ASN_NGAP_AMF_UE_NGAP_ID_t *>(mem);
                    asn::SetSigned64(ue->amfUeNgapId, id);
                });
        }
        std::cout << "Completed handling of UE and AMF contexts" << std::endl;

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
        std::cout << "Completed handling of asn_DEF_ASN_NGAP_UserLocationInformation" << std::endl;

    // Add UE Security Capabilities IE
    asn::ngap::AddProtocolIeIfUsable(*pdu, asn_DEF_ASN_NGAP_UESecurityCapabilities, 
                                    ASN_NGAP_ProtocolIE_ID_id_UESecurityCapabilities, ASN_NGAP_Criticality_ignore, 
                                    [this, &ueSecurityCapability](void *mem) {
        // Interpret memory as UESecurityCapabilities ASN.1 structure
        auto &secCap = *reinterpret_cast<ASN_NGAP_UESecurityCapabilities_t *>(mem);

        // Prepare buffers for encryption and integrity protection algorithms
        uint8_t encryptionAlgorithms[2] = {0};
        uint8_t integrityProtectionAlgorithms[2] = {0};

        // Populate the NR encryption algorithms (e.g., EA0, 128-EA1, etc.)
        encryptionAlgorithms[0] |= (ueSecurityCapability.b_5G_EA0 << 7) |
                                (ueSecurityCapability.b_128_5G_EA1 << 6) |
                                (ueSecurityCapability.b_128_5G_EA2 << 5) |
                                (ueSecurityCapability.b_128_5G_EA3 << 4) |
                                (ueSecurityCapability.b_5G_EA4 << 3) |
                                (ueSecurityCapability.b_5G_EA5 << 2) |
                                (ueSecurityCapability.b_5G_EA6 << 1) |
                                (ueSecurityCapability.b_5G_EA7);

        // Populate the next byte if required for further encryption algorithms (if supported)
        // encryptionAlgorithms[1] |= (additional encryption algorithm bits);

        // Populate the NR integrity protection algorithms (e.g., IA0, 128-IA1, etc.)
        integrityProtectionAlgorithms[0] |= (ueSecurityCapability.b_5G_IA0 << 7) |
                                            (ueSecurityCapability.b_128_5G_IA1 << 6) |
                                            (ueSecurityCapability.b_128_5G_IA2 << 5) |
                                            (ueSecurityCapability.b_128_5G_IA3 << 4) |
                                            (ueSecurityCapability.b_5G_IA4 << 3) |
                                            (ueSecurityCapability.b_5G_IA5 << 2) |
                                            (ueSecurityCapability.b_5G_IA6 << 1) |
                                            (ueSecurityCapability.b_5G_IA7);

        // Memory allocation for ASN.1 fields (ensure you allocate memory dynamically if needed)
        secCap.nRencryptionAlgorithms.buf = (uint8_t *)calloc(1, sizeof(encryptionAlgorithms));
        if (secCap.nRencryptionAlgorithms.buf == nullptr) {
            throw std::runtime_error("Memory allocation failed for NR encryption algorithms");
        }
        memcpy(secCap.nRencryptionAlgorithms.buf, encryptionAlgorithms, sizeof(encryptionAlgorithms));
        secCap.nRencryptionAlgorithms.size = sizeof(encryptionAlgorithms);
        secCap.nRencryptionAlgorithms.bits_unused = 0;

        // Memory allocation for integrity protection algorithms
        secCap.nRintegrityProtectionAlgorithms.buf = (uint8_t *)calloc(1, sizeof(integrityProtectionAlgorithms));
        if (secCap.nRintegrityProtectionAlgorithms.buf == nullptr) {
            throw std::runtime_error("Memory allocation failed for NR integrity protection algorithms");
        }
        memcpy(secCap.nRintegrityProtectionAlgorithms.buf, integrityProtectionAlgorithms, sizeof(integrityProtectionAlgorithms));
        secCap.nRintegrityProtectionAlgorithms.size = sizeof(integrityProtectionAlgorithms);
        secCap.nRintegrityProtectionAlgorithms.bits_unused = 0;

        // Optionally, if the system uses EUTRA (LTE) encryption and integrity algorithms, allocate and set them similarly
        // Example:
        // secCap.eUTRAencryptionAlgorithms.buf = ...;
        // secCap.eUTRAintegrityProtectionAlgorithms.buf = ...;

    });


    // Add the PDUSessionResourceToBeSwitchedDLList IE
    asn::ngap::AddProtocolIeIfUsable(*pdu, asn_DEF_ASN_NGAP_PDUSessionResourceToBeSwitchedDLList, 
                                        ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceToBeSwitchedDLList, 
                                        ASN_NGAP_Criticality_reject, [pduList = std::make_shared<ASN_NGAP_PDUSessionResourceToBeSwitchedDLList>(*pduList)](void *mem) {
            auto *list = reinterpret_cast<ASN_NGAP_PDUSessionResourceToBeSwitchedDLList *>(mem);
            *list = *pduList;
        });
        //free(octetString);

        std::cout << "Completed handling of asn_DEF_ASN_NGAP_PDUSessionResourceToBeSwitchedDLList" << std::endl;


    }
    std::cout << "Completed handling of ASN_NGAP_UESecurityCapabilities_t" << std::endl;

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
        std::cout << "Completed handling of asn_check_constraints" << std::endl;
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
        std::cout << "Completed else statement" << std::endl;

    }
    //asn::Free(asn_DEF_ASN_NGAP_PDUSessionResourceToBeSwitchedDLList, pduList);
    //asn::Free(asn_DEF_ASN_NGAP_PDUSessionResourceToBeSwitchedDLItem, item);
    //free(pduList->list.array);
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
        case ASN_NGAP_SuccessfulOutcome__value_PR_PathSwitchRequestAcknowledge:
            m_logger->info("Path Switch Request Acknowledge Received. ");
            receivePSRAck(amf->ctxId, &value.choice.PathSwitchRequestAcknowledge);
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
