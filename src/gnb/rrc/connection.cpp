//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "task.hpp"
#include <utils/octet_view.hpp>
#include <gnb/ngap/task.hpp>
#include <lib/rrc/encode.hpp>

#include <asn/ngap/ASN_NGAP_FiveG-S-TMSI.h>
#include <asn/rrc/ASN_RRC_BCCH-BCH-Message.h>
#include <asn/rrc/ASN_RRC_BCCH-DL-SCH-Message.h>
#include <asn/rrc/ASN_RRC_CellGroupConfig.h>
#include <asn/rrc/ASN_RRC_DL-CCCH-Message.h>
#include <asn/rrc/ASN_RRC_DL-DCCH-Message.h>
#include <asn/rrc/ASN_RRC_DLInformationTransfer-IEs.h>
#include <asn/rrc/ASN_RRC_DLInformationTransfer.h>
#include <asn/rrc/ASN_RRC_PCCH-Message.h>
#include <asn/rrc/ASN_RRC_Paging.h>
#include <asn/rrc/ASN_RRC_PagingRecord.h>
#include <asn/rrc/ASN_RRC_PagingRecordList.h>
#include <asn/rrc/ASN_RRC_RRCRelease-IEs.h>
#include <asn/rrc/ASN_RRC_RRCRelease.h>
#include <asn/rrc/ASN_RRC_RRCSetup-IEs.h>
#include <asn/rrc/ASN_RRC_RRCSetup.h>
#include <asn/rrc/ASN_RRC_RRCSetupComplete-IEs.h>
#include <asn/rrc/ASN_RRC_RRCSetupComplete.h>
#include <asn/rrc/ASN_RRC_RRCSetupRequest.h>
#include <asn/rrc/ASN_RRC_UL-CCCH-Message.h>
#include <asn/rrc/ASN_RRC_UL-CCCH1-Message.h>
#include <asn/rrc/ASN_RRC_UL-DCCH-Message.h>
#include <asn/rrc/ASN_RRC_ULInformationTransfer-IEs.h>
#include <asn/rrc/ASN_RRC_ULInformationTransfer.h>
#include <iostream>
namespace nr::gnb
{

void GnbRrcTask::receiveRrcSetupRequest(int ueId, const ASN_RRC_RRCSetupRequest &msg)
{
    auto *ue = tryFindUe(ueId);
    if (ue)
    {
        // TODO: handle this more properly
        m_logger->warn("Discarding RRC Setup Request, UE context already exists");
        return;
    }

    if (msg.rrcSetupRequest.ue_Identity.present == ASN_RRC_InitialUE_Identity_PR_NOTHING)
    {
        m_logger->err("Bad constructed RRC message ignored");
        return;
    }

    ue = createUe(ueId);

    if (msg.rrcSetupRequest.ue_Identity.present == ASN_RRC_InitialUE_Identity_PR_ng_5G_S_TMSI_Part1)
    {
        std::cout<<"msg.rrcSetupRequest.ue_Identity.present == ASN_RRC_InitialUE_Identity_PR_ng_5G_S_TMSI_Part1"<<std::endl;
        ue->initialId = asn::GetBitStringLong<39>(msg.rrcSetupRequest.ue_Identity.choice.ng_5G_S_TMSI_Part1);
        ue->isInitialIdSTmsi = true;
    }
    else
    {
        std::cout<<"else statement: msg.rrcSetupRequest.ue_Identity.present != ASN_RRC_InitialUE_Identity_PR_ng_5G_S_TMSI_Part1"<<std::endl;
        ue->initialId = asn::GetBitStringLong<39>(msg.rrcSetupRequest.ue_Identity.choice.randomValue);
        ue->isInitialIdSTmsi = false;
    }

    ue->establishmentCause = static_cast<int64_t>(msg.rrcSetupRequest.establishmentCause);
    std::cout<<"ue->establishmentCause: " <<ue->establishmentCause<<std::endl;
    // Prepare RRC Setup
    auto *pdu = asn::New<ASN_RRC_DL_CCCH_Message>();
    pdu->message.present = ASN_RRC_DL_CCCH_MessageType_PR_c1;
    pdu->message.choice.c1 = asn::NewFor(pdu->message.choice.c1);
    pdu->message.choice.c1->present = ASN_RRC_DL_CCCH_MessageType__c1_PR_rrcSetup;
    auto &rrcSetup = pdu->message.choice.c1->choice.rrcSetup = asn::New<ASN_RRC_RRCSetup>();
    rrcSetup->rrc_TransactionIdentifier = getNextTid();
    rrcSetup->criticalExtensions.present = ASN_RRC_RRCSetup__criticalExtensions_PR_rrcSetup;
    auto &rrcSetupIEs = rrcSetup->criticalExtensions.choice.rrcSetup = asn::New<ASN_RRC_RRCSetup_IEs>();

    ASN_RRC_CellGroupConfig masterCellGroup{};
    masterCellGroup.cellGroupId = 0;

    asn::SetOctetString(rrcSetupIEs->masterCellGroup,
                        rrc::encode::EncodeS(asn_DEF_ASN_RRC_CellGroupConfig, &masterCellGroup));

    m_logger->info("RRC Setup for UE[%d]", ueId);

    sendRrcMessage(ueId, pdu);
    asn::Free(asn_DEF_ASN_RRC_DL_CCCH_Message, pdu);
}

void GnbRrcTask::receiveRrcSetupComplete(int ueId, const ASN_RRC_RRCSetupComplete &msg)
{
    auto *ue = findUe(ueId);
    if (!ue)
        return;

    auto setupComplete = msg.criticalExtensions.choice.rrcSetupComplete;

    if (msg.criticalExtensions.choice.rrcSetupComplete)
    {
        // Handle received 5G S-TMSI if any
        if (msg.criticalExtensions.choice.rrcSetupComplete->ng_5G_S_TMSI_Value)
        {
            ue->sTmsi = std::nullopt;

            auto &sTmsiValue = msg.criticalExtensions.choice.rrcSetupComplete->ng_5G_S_TMSI_Value;
            if (sTmsiValue->present == ASN_RRC_RRCSetupComplete_IEs__ng_5G_S_TMSI_Value_PR_ng_5G_S_TMSI)
            {
                ue->sTmsi = GutiMobileIdentity::FromSTmsi(asn::GetBitStringLong<48>(sTmsiValue->choice.ng_5G_S_TMSI));
            }
            else if (sTmsiValue->present == ASN_RRC_RRCSetupComplete_IEs__ng_5G_S_TMSI_Value_PR_ng_5G_S_TMSI_Part2)
            {
                if (ue->isInitialIdSTmsi)
                {
                    int64_t part2 = asn::GetBitStringLong<9>(sTmsiValue->choice.ng_5G_S_TMSI_Part2);
                    ue->sTmsi = GutiMobileIdentity::FromSTmsi((part2 << 39) | (ue->initialId));
                }
            }
        }
    }

    auto w = std::make_unique<NmGnbRrcToNgap>(NmGnbRrcToNgap::INITIAL_NAS_DELIVERY);
    w->ueId = ueId;
    w->pdu = asn::GetOctetString(setupComplete->dedicatedNAS_Message);
    w->rrcEstablishmentCause = ue->establishmentCause;
    w->sTmsi = ue->sTmsi;

    m_base->ngapTask->push(std::move(w));
}

void GnbRrcTask::createNewConnection(const OctetString& data) {
    OctetView stream(data.data(), data.length());  // Create OctetView to decode data

    // Decoding ueId as a 4-byte integer
    int ueId = stream.read4UI();
    auto *ue = tryFindUe(ueId);
    if (ue) {
        m_logger->warn("Discarding RRC Setup Request, UE context already exists");
        return;
    }
    ue = createUe(ueId);

    // Decoding initialId as an 8-byte integer
    ue->initialId = stream.read8UL();

    // Decoding isInitialIdSTmsi as a boolean (1 byte)
    ue->isInitialIdSTmsi = static_cast<bool>(stream.readI());

    // Decoding establishmentCause as an 8-byte integer
    ue->establishmentCause = stream.read8L();

    // Decoding optional sTmsi
    uint8_t sTmsiPresent = stream.readI();
    if (sTmsiPresent == 1) {
        ue->sTmsi = std::nullopt;  // No sTmsi provided

        /*GutiMobileIdentity sTmsi;

        // Decoding amfRegionId (1-byte)
        sTmsi.amfRegionId = stream.read();

        // Decoding amfSetId (10 bits) and amfPointer (6 bits)
        uint8_t amfSetIdUpper = stream.readI();  // Upper 8 bits of amfSetId
        uint8_t amfSetIdLowerAndPointer = stream.readI();  // Lower 2 bits of amfSetId and 6 bits of amfPointer

        sTmsi.amfSetId = (amfSetIdUpper << 2) | (amfSetIdLowerAndPointer >> 6);  // Combine the two parts of amfSetId
        sTmsi.amfPointer = amfSetIdLowerAndPointer & 0x3F;  // Mask to get the lower 6 bits for amfPointer

        // Decoding tmsi (octet4), which is 4 bytes
        octet4 tmsiValue = stream.read4();
        memcpy(sTmsi.tmsi, tmsiValue, sizeof(octet4));  // Correctly copy the tmsi array

        // Prepare a BIT_STRING_t for the tmsi
        BIT_STRING_t tmsiBitString;
        tmsiBitString.buf = reinterpret_cast<uint8_t*>(&sTmsi.tmsi[0]);  // Point to the first element of the tmsi array
        tmsiBitString.size = sizeof(octet4);  // Size of tmsi in bytes
        tmsiBitString.bits_unused = 0;

        // Combine tmsi and assign to sTmsi
        ue->sTmsi = GutiMobileIdentity::FromSTmsi(asn::GetBitStringLong<48>(tmsiBitString));*/

    } else {
        ue->sTmsi = std::nullopt;  // No sTmsi provided
    }
    m_logger->info("RRC Setup Request for UE[%d]", ueId);

}

void GnbRrcTask::SendNewConnectionReq(int ueId)
{
    // Prepare RRC Setup
    auto *pdu = asn::New<ASN_RRC_DL_CCCH_Message>();
    pdu->message.present = ASN_RRC_DL_CCCH_MessageType_PR_c1;
    pdu->message.choice.c1 = asn::NewFor(pdu->message.choice.c1);
    pdu->message.choice.c1->present = ASN_RRC_DL_CCCH_MessageType__c1_PR_rrcSetup;
    auto &rrcSetup = pdu->message.choice.c1->choice.rrcSetup = asn::New<ASN_RRC_RRCSetup>();
    rrcSetup->rrc_TransactionIdentifier = getNextTid();
    rrcSetup->criticalExtensions.present = ASN_RRC_RRCSetup__criticalExtensions_PR_rrcSetup;
    auto &rrcSetupIEs = rrcSetup->criticalExtensions.choice.rrcSetup = asn::New<ASN_RRC_RRCSetup_IEs>();

    ASN_RRC_CellGroupConfig masterCellGroup{};
    masterCellGroup.cellGroupId = 0;

    asn::SetOctetString(rrcSetupIEs->masterCellGroup,
                        rrc::encode::EncodeS(asn_DEF_ASN_RRC_CellGroupConfig, &masterCellGroup));

    m_logger->info("RRC Setup for UE[%d]", ueId);

    sendRrcMessage(ueId, pdu);
    asn::Free(asn_DEF_ASN_RRC_DL_CCCH_Message, pdu);
}


} // namespace nr::gnb
