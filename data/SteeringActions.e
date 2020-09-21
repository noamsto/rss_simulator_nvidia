// MTL-HEADER //////////////////////////////////////////////////////////////////////
// This Program is the Confidential and Proprietary product of
// Mellanox Technologies LTD. Any unauthorized use, reproduction
// or transfer of this program is strictly prohibited.
// Copyright (c) 1999 by Mellanox Technologies LTD All Rights Reserved.
// EOH /////////////////////////////////////////////////////////////////////////////

<'
import SteeringActions_ih;
import SteeringActionsCov;

extend SteeringActions{
    PerformActionsPerEntry(Packet : *ParserEntryPacket,SE : SteeringEntry,EntryGvmi : uint(bits : 16)) is also{
        ResetSizeToBeInsertedOrRemovedForCurrEntry();
        case(SE.steering_entry_desc.entry_format){
            rx_rss: {
                RssAction=TRUE;
                if(IteratorActionHasOccured){
                    emit RssAfterIterator;
                };
                PerformRssActions(Packet,SE,EntryGvmi);
                PerformRssTirActions(SE);
                UpdateOrderingContext(Packet, SE, {}, TRUE);
            };
            [match,match_mask_bwc_bytes,match_mask_bwc_dws,match_mask_bytes,match_mask_dws,match_ranges,extended_match_ranges] : {PerformActions(Packet,SE,EntryGvmi)};
            [jumbo_match]                                                                                : {};
        };
    };

    GetRssTableQpNum(ExpectedPkt : ParserEntryPacket,SE : SteeringEntry,EntryGvmi : uint(bits : 16)) : RssActions is {
        var Packet : NetworkPacket = ExpectedPkt.PsaNetworkPacket;
        result = new;
        var RssDataBase : RssDataBase = HANDLERS(LocalQp).FlowGenerator.RssDataBaseList.first(it.RssKey == SE.rss_key);
        result.RssHashResult = GetRssHash(RssDataBase,ExpectedPkt,SE);
        var HashResult                    : uint          = SE.rss_indirection_table_size > 0 ? result.RssHashResult[SE.rss_indirection_table_size-1:0] : 0;
        var NumOfQpIndexesInSteeringEntry : uint          = 512 / DecodeRssQpnSize(SE.rss_qpn_size);
        var RssSteeringCacheLineId        : uint          = HashResult == 0 ? 0 : HashResult/NumOfQpIndexesInSteeringEntry;
        var QpListAddress                 : uint(bits:64) = HANDLERS(Mem).Icm.IndexToIcmVa(EntryGvmi,SteeringQpList,SE.indirection_table_pointer + RssSteeringCacheLineId);
        var QpList                        : list of byte  = HANDLERS(Mem).Icm.ReadIcmVa(EntryGvmi,SteeringQpList,QpListAddress,64);
        HashResult = HashResult % NumOfQpIndexesInSteeringEntry;
        var QpNumber : uint = GetQpNumberFromRssQpList(QpList, HashResult, SE);
        result.QpNumber    = QpNumber;
        result.Gvmi        = GetGvmiNumberFromRssGvmiList(QpList, HashResult, SE,EntryGvmi);
        result.RssHashType = GetRssHashType(SE);
    };

    GetRssHashType(SE : SteeringEntry) : uint(bits : PSA_RX_RESULTS_DESC_RSS_HASH_TYPE_WIDTH) is {
        result[1:0] = SE.steering_entry_rss_params_desc.rss_ip_src_type;
        result[3:2] = SE.steering_entry_rss_params_desc.rss_ip_dest_type;
        result[5:4] = SE.steering_entry_rss_params_desc.rss_l4_src_type;
        result[7:6] = SE.steering_entry_rss_params_desc.rss_l4_dest_type;
    };

    DecodeRssQpnSize(RssQpnSize : uint):uint is {
        case RssQpnSize {
            0 : { result = 32; };
            1 : { result = 16; };
            2 : { result = 8; };
            3 : { DUTError(937,"RssDataBase.QpnSize=3 which is reserved"); };
        };
    };

    GetRssHash(RssDataBase : RssDataBase,ExpectedPkt : ParserEntryPacket, SE : SteeringEntry) : uint is {
        var Packet : NetworkPacket = ExpectedPkt.PsaNetworkPacket;
        var SteeringParams : SteeringParams = new;
        RssDataBase                        = new;
        RssDataBase.RssMode                = RssGroup;
        RssDataBase.RssSubType             = SE.steering_entry_rss_hash_indirect_desc.rss_type.as_a(RssSubType);
        RssDataBase.RssL4Dst               = SE.steering_entry_rss_params_desc.rss_l4_dest_type.as_a(RssL4Type);
        RssDataBase.RssL4Src               = SE.steering_entry_rss_params_desc.rss_l4_src_type.as_a(RssL4Type);
        RssDataBase.RssL3Dst               = SE.steering_entry_rss_params_desc.rss_ip_dest_type.as_a(RssL3Type);
        RssDataBase.RssL3Src               = SE.steering_entry_rss_params_desc.rss_ip_src_type.as_a(RssL3Type);
        RssDataBase.SymmetricIpAddress     = SE.steering_entry_rss_params_desc.symmetric_ip_address.as_a(bool);
        RssDataBase.SymmetricTcpUdpAddress = SE.steering_entry_rss_params_desc.symmetric_tcp_udp_address.as_a(bool);
        RssDataBase.RssKey                 = SE.rss_key;
        var SlicedNetworkPacket : NetworkPacket = UNITS(Psa, InstanceIndex).SteeringWbVerifier.UnpackSizeOfBytes(ExpectedPkt,Packet.PackedPacket,REWRITE_BUFFER_SIZE);
        var RssPkt : NetworkPacket = (RssDataBase.RssSubType == ToplitzInner) ? GetEthPacket(SlicedNetworkPacket).InnerPacket : GetEthPacket(SlicedNetworkPacket);
        if RssPkt == NULL{
            DUTError(10,appendf("RssDataBase with index %s has RssSubType = %s but packet is null",RssDataBase.RssIndex,RssDataBase.RssSubType));
        };
        HANDLERS(LocalQp).FlowGenerator.BuildSteeringParamsFromPacket(SteeringParams,RssPkt);
        result = HANDLERS(LocalQp).FlowGenerator.CalcRssHash(RssDataBase,SteeringParams) ^ AccumulatedHashRegister;
    };

    GetQpNumberFromRssQpList(QpList : list of byte,HashResult : uint,SE : SteeringEntry) : uint is {
        result = SE.rss_indirection_table_base_qpn;
        var GvmiBitMask : uint = SE.gvmi_rss_enable ? HANDLERS(Config).CrSpaceConfig.Log2NumberOfEntriesInGvmiList : 0;
        case (SE.rss_qpn_size) {
            0 : {
                result[7:0]   = QpList[(4*HashResult)+3];
                result[15:8]  = QpList[(4*HashResult)+2];
                result[23:16] = QpList[(4*HashResult)+1];
            };
            1 : {
                result[7:0]                = QpList[(2*HashResult)+1];
                result[15 - GvmiBitMask:8] = QpList[(2*HashResult)][7 - GvmiBitMask:0];
            };
            2 : {
                result[7 - GvmiBitMask:0] = QpList[(HashResult)][7 - GvmiBitMask:0];
            };
        };
    };
    GetGvmiNumberFromRssGvmiList(QpList : list of byte,HashResult : uint,SE : SteeringEntry,EntryGvmi : uint(bits :16)) : uint(bits : 16) is{
        if not SE.gvmi_rss_enable {return SE.steering_entry_rss_hash_indirect_desc.gvmi_gvmi_list_index;};
        var GvmiIndex : byte;
        case (SE.rss_qpn_size) {
            0 : {
                GvmiIndex = QpList[(4*HashResult)][7:8 - HANDLERS(Config).CrSpaceConfig.Log2NumberOfEntriesInGvmiList];
            };
            1 : {
                GvmiIndex = QpList[(2*HashResult)][7:8 - HANDLERS(Config).CrSpaceConfig.Log2NumberOfEntriesInGvmiList];
            };
            2 : {
                GvmiIndex = QpList[(HashResult)][7:8 - HANDLERS(Config).CrSpaceConfig.Log2NumberOfEntriesInGvmiList];
            };
        };
        return UpdateRssTableGvmiNum(GvmiIndex,SE,EntryGvmi);
    };

    UpdateRssTableGvmiNum(GvmiIndex : byte,SE : SteeringEntry,EntryGvmi : uint(bits : 16)) : uint(bits : 16) is {
        var RssGvmiListGvmi       : uint (bits:16) = (HANDLERS(Config).CrSpaceConfig.TakeGvmiListIcmMsbFromCrspace == 1) ? HANDLERS(Config).CrSpaceConfig.GvmiListIcmMsb : EntryGvmi;
        var RssGvmiListEntryIndex : uint (bits:16) = SE.gvmi_list_index[15:6-HANDLERS(Config).CrSpaceConfig.Log2GvmiListEntrySize];
        var RssGvmiListAddress    : uint(bits:64)  = HANDLERS(Mem).Icm.IndexToIcmVa(RssGvmiListGvmi,SteeringRssGvmiList,RssGvmiListEntryIndex);
        messagef(HIGH,"RssGvmiList address =%s",RssGvmiListAddress);
        var RssGvmiListsInCacheLine : list of byte = HANDLERS(Mem).Icm.ReadIcmVa(RssGvmiListGvmi,SteeringRssGvmiList,RssGvmiListAddress,64);
        var RssGvmiListSize         : uint         = (1<<HANDLERS(Config).CrSpaceConfig.Log2GvmiListEntrySize);
        var RssGvmiList             : list of byte;
        if RssGvmiListSize == ICM_CACHE_LINE_SIZE {
            RssGvmiList = RssGvmiListsInCacheLine;
        } else {
            var RssGvmiListIndex : uint = SE.gvmi_list_index[6-HANDLERS(Config).CrSpaceConfig.Log2GvmiListEntrySize-1 : 0];
            RssGvmiList = RssGvmiListsInCacheLine[(RssGvmiListSize*RssGvmiListIndex)..(RssGvmiListSize*(RssGvmiListIndex+1)-1)];
        };

        result[7:0]  = RssGvmiList[(GvmiIndex*2)+1];
        result[15:8] = RssGvmiList[(GvmiIndex*2)];
    };


    PerformRssActions(ExpectedPkt : ParserEntryPacket, SE : SteeringEntry,EntryGvmi : uint(bits : 16)) is {
        var Packet : NetworkPacket = ExpectedPkt.PsaNetworkPacket;
        if RssQp != NULL {return};
        RssQp               = GetRssTableQpNum(ExpectedPkt, SE, EntryGvmi);
        RssQp.SteeringEntry = SE;
        XqpnVld             = TRUE;
        messagef(MEDIUM,"TirActions:\t"){
            RssQp.PrintMe()
        };
        RssQp.CollectCoverage();
    };

    PerformRssTirActions(SE : SteeringEntry) is {
        TirActions                     = new;
        TirActions.TimeStampFromPort   = SE.steering_entry_rss_hash_indirect_desc.utc;
        TirActions.TimeStampFromOrigin = SE.steering_entry_rss_hash_indirect_desc.timestamp_from_port;
        TirActions.ClassifiedAsTunnel  = SE.steering_entry_rss_hash_indirect_desc.classified_as_tunneled;
        messagef(MEDIUM,"TirActions:\t"){
            TirActions.PrintMe()
        };
    };

    TerminateByAction(ActionId : SteeringTreeNodeType, ExpectedPkt : ParserEntryPacket) : bool is {
        return ExpectedPkt.PsaControlDesc.packet_source == rx0 and ActionId == queue_id_sel or
        ExpectedPkt.PsaControlDesc.packet_source        == rx1 and ActionId in [ipsec_decryption,macsec_decryption] or
        ExpectedPkt.PsaControlDesc.packet_source        == sx and ActionId  == transmit_now;
    };

    UpdateOrderingContext(Packet : *ParserEntryPacket, SE : SteeringEntry, ActionsList: list of SteeringAction, isRss: bool = FALSE) is {
        var EnvSlice := GET_PSA_FATHER.SteeringWbVerifier.EnvSlices[Packet.SliceId];
        var terminates     : byte = (EnvSlice.CacheHitDecision == HitNop) ? 1 : 0;
        var already_exited : bool = FALSE;//used to limit only one of the possible 3 actions of this entry as going to SW - either the first ordered action or the very last action(if no ordered actions and terminate)
        var AdditionalInfo : SteeringTreeNodeAdditionalInfo;
        EnvSlice.OrderingContext.SetPacketSource(Packet.PsaControlDesc.packet_source);
        if isRss {
            if terminates > 0 {
                EnvSlice.OrderingContext.SetActionInSteeringTree(rss, TRUE, Packet.IterationLevel, AdditionalInfo, terminates);
                EnvSlice.OrderingContext.ReturnInSteeringTree();
            } else {
                EnvSlice.OrderingContext.AddActionToSteeringTree(rss, TRUE, Packet.IterationLevel, AdditionalInfo);
            };
            return;
        };
        for each (Action) in ActionsList{
            var ActionId : SteeringTreeNodeType = Action.ActionId;

            //translate the ActionId to SteeringTreeNodeType for better readability for specific cases
            case (ActionId){
                misc : {
                    if Action.steering_entry_action_single_desc.lock_action_enable == 1 and Action.steering_entry_action_single_desc.lock_action_type == 1 {ActionId = misc_lock;};
                    if Action.steering_entry_action_single_desc.lock_action_enable == 1 and Action.steering_entry_action_single_desc.lock_action_type == 0 {ActionId = misc_unlock;};
                };
                aso : {
                    if Action.steering_entry_action_double_desc.aso_check_ordering == 0 {ActionId = aso_unord;}
                    else {
                        AdditionalInfo = new SteeringTreeNodeAdditionalInfo with {
                            it.ChangeOrderingTag = Action.steering_entry_action_double_desc.change_ordering_tag;
//                            it.NewOrderingTag = CalcCRC8(BusToListOfBytes(Action.steering_entry_action_double_desc.aso_context_number, 4));
                        };                       
                    };
                };
                tir : {
                    if me.QpList != NULL {ActionId   = qp_list;};
                    if me.InlineQp != NULL {ActionId = inline_qpn;};
                };
                transmit : {
                    if Action.steering_entry_action_single_desc.sx_transmit_now == 1 {ActionId = transmit_now;};
                };
            };
            //add it to the tree depending on the situation
            //determines the shape of the tree
            if TerminateByAction(ActionId, Packet) {terminates = 2;};
            var exit_to_sw                                                                                  : bool = ((ActionId in [aso, aso_unord, transmit_now, queue_id_sel, inline_qpn, qp_list, tir]) or TerminateByAction(ActionId, Packet) );
            var ref_iteration_level := (ActionsList.has(it.ActionId==iterator)) ? Packet.IterationLevel - 1 : Packet.IterationLevel;
            messagef(FULL," 7 :: PrepareOrderedDomainInfo - adding to steering tree action: %s exit to sw: %s", ActionId.to_string(), exit_to_sw.to_string());
            if index < ActionsList.size() - 1 {//not the last action for the entry so not a leaf in the tree
                if ActionId in [qp_list] {
                    for i from 1 to EnvSlice.SteeringActions.QpList.NumOfQp {
                        EnvSlice.OrderingContext.AddActionToSteeringTree(ActionId, exit_to_sw, ref_iteration_level, AdditionalInfo, 0);
                    };
                } else {
                    EnvSlice.OrderingContext.AddActionToSteeringTree(ActionId, exit_to_sw, ref_iteration_level, AdditionalInfo, 0);
                };
            } else {

                if ActionId == iterator {
                    messagef(FULL," 7 :: PrepareOrderedDomainInfo - num branches : %d", Action.steering_entry_action_double_desc.num_of_iterations);
                    EnvSlice.OrderingContext.AddIteratorToSteeringTree(Action.steering_entry_action_double_desc.num_of_iterations, ref_iteration_level, terminates);
                }
                else {
                    if ActionId in [qp_list] {
                        for i from 1 to EnvSlice.SteeringActions.QpList.NumOfQp-1 {
                            EnvSlice.OrderingContext.AddActionToSteeringTree(ActionId, exit_to_sw, ref_iteration_level, AdditionalInfo);
                        };
                    };
                    if terminates > 0 {//this is a leaf; continue construction of the next branch(es)
//                   messagef(LOW," 7 :: PrepareOrderedDomainInfo - return in tree due to %s", SE.NextTableBase_39_6 == 0 ? "NextTableBase_39_6" : "TerminateByAction");
                        EnvSlice.OrderingContext.SetActionInSteeringTree(ActionId, (exit_to_sw or terminates > 0) and not already_exited , ref_iteration_level, AdditionalInfo, terminates);
                        EnvSlice.OrderingContext.ReturnInSteeringTree();
                    } else {
                        EnvSlice.OrderingContext.AddActionToSteeringTree(ActionId, exit_to_sw, ref_iteration_level, AdditionalInfo, terminates);
                    };

                };
            }; //end if that determines the shape of the tree
            already_exited = already_exited or exit_to_sw;
        };//end for Actions

    };

    // Calculate the bytes to be removed from/inserted to the packet when in ASO action and HAA = 1 
    CalculateRemovedOrInsertedBytes(Packet : *ParserEntryPacket, SE : SteeringEntry, EntryGvmi : uint(bits : 16), ActionsList : list of SteeringAction) is {
        if SE.HashAfterAction == 0 { return; };
        for each (Action) in ActionsList {
            if Action.ActionId not in [remove_by_size, insert_inline, modify_list] {continue; };
            var ActionListUintData            : list of uint                            = GetActionsAsData(Packet,Action,EntryGvmi);
            var RxSxType                      : RxSxType                                = (Packet.PsaControlDesc.packet_source in [sx]) ? SX : RX;
            var CalculatedModificationActions : list of SteeringNodeModificationActions = UnpackModificationList(ActionListUintData,RxSxType);
            for each (ModificationAction) in CalculatedModificationActions {
                var ActionType : SteeringNodeActionType = RxSxType == RX ? ModificationAction.RxModificationActionType : ModificationAction.SxModificationActionType;
                case ActionType {
                    [RemoveBySize]: {
                        SizeToBeRemoved = ModificationAction.RemoveSize * 2;
                    }; 
                    [InsertWithInline]: {
                        SizeToBeInserted = STEERING_ENTRY_ACTION_DOUBLE_DESC_INSERT_DATA_INLINE_WIDTH/8; // in bytes
                    };
                };
            };
        };
        ChangePktLengthInHAA =  TRUE;
    };
    
    ResetSizeToBeInsertedOrRemovedForCurrEntry() is {
        SizeToBeRemoved      = 0;
        SizeToBeInserted     = 0;
        ChangePktLengthInHAA = FALSE;
    };
    
    PerformActions(Packet : *ParserEntryPacket,SE : SteeringEntry,EntryGvmi : uint(bits : 16)) is {
        var ActionsList   : list of SteeringAction;
        var ActionListStr : string;
        case(Packet.PsaControlDesc.packet_source) { // steering constraints.
            rx0: {
                ActionsList = SE.InlineActionList.all(it.ActionId not in [RX_TERMINATOR_ACTIONS,SX_ONLY_ACTIONS]);
            };
            sx: {
                ActionsList = SE.InlineActionList.all(it.ActionId not in [RX_ONLY_ACTIONS]);
            };
            rx1: {
                ActionsList = SE.InlineActionList.all(it.ActionId not in [queue_id_sel,SX_ONLY_ACTIONS]);
            };
            rx2: {
                ActionsList = SE.InlineActionList.all(it.ActionId not in [ipsec_decryption,macsec_decryption,queue_id_sel,SX_ONLY_ACTIONS]);
            };
        };
        if ActionsList.has(it.ActionId == iterator) {
            ActionListStr = appendf("iterator ");
        };
        ActionsList = {ActionsList.all(it.ActionId not in [iterator]);ActionsList.all(it.ActionId in [iterator])};
        XqpnVld     = SE.InlineActionList.has(it.ActionId in [RX_TERMINATOR_ACTIONS]); //Indication that Xqpn is valid for next unit.
        PushPopActionList.clear();
        CountOnSourceGvmi = FALSE;
        CountOnDestGvmi   = FALSE;
        if(Packet.PsaNetworkPacket.HasHeader(MAC) and Packet.PsaNetworkPacket.MACHeader().HasVlan){
            GET_PSA_FATHER.SteeringWbVerifier.ListOfActionsOnPackets.key(Packet.PsaNetworkPacket.FcId).PrevVlanPrio=Packet.PsaNetworkPacket.GetVlanPrio(-1,NULL);
        };
        
        CalculateRemovedOrInsertedBytes(Packet, SE, EntryGvmi, ActionsList); // for each in ActionList calculate if it adds/removes bytes from packet and how many. add/remove it from ASO packet_length via a global variable
        CurrSEHashAfterActionsPacketSize = Packet.PsaNetworkPacket.PackedPacket.size() - SizeToBeRemoved + SizeToBeInserted;    
        
        for each (Action) in ActionsList{
            case (Action.ActionId){
                nop        : {};
                transmit   : {UpdateSxTransmit(Action)};
                inline_qpn : {UpdateInlineQp(Action,EntryGvmi)};
                qp_list    : {UpdateQpList(Action,EntryGvmi,EntryGvmi)};
                tir        : {UpdateTir(Action,EntryGvmi)};
                [add,set,copy,
                    remove_by_size,
                    remove_headers,
                    insert_inline,
                    insert_pointer,
                    modify_list,
                    accelerated_list]: {UpdateModifyList(Packet, Action,EntryGvmi);};
                queue_id_sel         : {UpdateQueueId(Action)};
                iterator             : {UpdateIterator(Packet,Action,EntryGvmi,SE); };
                aso                  : {UpdateAso(Packet,SE,EntryGvmi,Action);};
                ipsec_decryption     : {UpdateIPSecDecryption(Packet, Action, EntryGvmi);};
                ipsec_encryption     : {UpdateIPSecEncryption(Packet, Action, EntryGvmi);};
                macsec_encryption    : {UpdateMACSecEncryption(Packet, Action, EntryGvmi);}; //TODO complete
                macsec_decryption    : {UpdateMACSecDecryption(Packet, Action, EntryGvmi);};
                flow_tag             : {UpdateFlowTag(Action)};
                tls                  : {UpdateTlsIndex(Action)};
                port_selection       : {UpdatePortSelection(Action, Packet)};
                misc                 : {};
                trailer              : {UpdateTrailer(Packet, Action, EntryGvmi)};
                count_on_source_gvmi : {UpdateCount(TRUE, Packet, Action, EntryGvmi)};
                counter_id           : {UpdateCount(FALSE, Packet, Action, EntryGvmi)};
                default              : {DUTError(1,"Unknown steering action : %s",Action.ActionId)};
            };
            CollectSteeringAction(Action);
            if Action.ActionId == nop { continue; };
            CollectIteratorBeforeAndAfterActions(Action.ActionId,SE.Reparse);
            CollectPsaControlDesc(Packet,Action);
            GET_PSA_FATHER.SteeringWbVerifier.CollectPacketActionTypeState(Action,PE);
            var IsInIterator:bool=FALSE;
            if(Iterator != NULL and Iterator.IteratorList.size()>0){
                IsInIterator=TRUE;
            };
            GET_PSA_FATHER.SteeringWbVerifier.InsertNewAction(Action,Packet,SE,IsInIterator);
            ActionListStr = appendf("%s%s",ActionListStr,Packet.ActionAsAString(Action));
            GET_PSA_FATHER.SteeringWbVerifier.SteeringActionsTypeCov.TypeOccured(Action.ActionId);
        };
        UpdateCounterGvmi(Packet, EntryGvmi); // in case of rewrite on source_gvmi, counter update should be on the updated source_gvmi, regardless of action order
        UpdateOrderingContext(Packet, SE, ActionsList);
        if ActionsList.size()>0 and ActionsList.has(it.ActionId != nop) {
            Packet.PrintMsg("PsaActions",ActionListStr);
        };
    };

    CheckErrorInActions(ActionsList : list of SteeringAction) is {

    };

    UpdateIPSecDecryption(Packet : *ParserEntryPacket, Action : SteeringAction, EntryGvmi : uint(bits:16)) is {
        messagef(MEDIUM,"UpdateIPSecDecryption");
        Packet.IPSecDecrypt = TRUE;
        UpdateCryptoContext(Action, EntryGvmi, IPSecDecrypt);

    };

    UpdateIPSecEncryption(Packet : *ParserEntryPacket, Action : SteeringAction, EntryGvmi : uint(bits:16)) is {
        messagef(MEDIUM,"UpdateIPSecEncryption");
        Packet.IPSecEncrypt = TRUE;
        UpdateCryptoContext(Action, EntryGvmi, IPSecEncrypt);
    };
    
    UpdateMACSecDecryption(Packet : *ParserEntryPacket, Action : SteeringAction, EntryGvmi : uint(bits:16)) is {
        messagef(MEDIUM,"UpdateMACSecDecryption");
        Packet.MACSecDecrypt = TRUE;
        UpdateCryptoContext(Action, EntryGvmi, MACSecDecrypt);
    };

    UpdateMACSecEncryption(Packet : *ParserEntryPacket, Action : SteeringAction, EntryGvmi : uint(bits:16)) is {
        messagef(MEDIUM,"UpdateMACSecEncryption");
        Packet.MACSecEncrypt = TRUE;
        UpdateCryptoContext(Action, EntryGvmi, MACSecEncrypt);
    };

    UpdateCryptoContext(Action : SteeringAction, EntryGvmi : uint(bits:16), Crypto : CryptoActions) is {
        Crypto.Valid            = TRUE;
        Crypto.SaDbContextIndex = Action.steering_entry_action_single_desc.sadb_context;
        Crypto.Gvmi             = EntryGvmi;
        messagef(MEDIUM,"") {
            Crypto.PrintMe();
        };
    };

    UpdateTrailer(Packet : *ParserEntryPacket, Action : SteeringAction, EntryGvmi : uint(bits:16)) is {
        TrailerOperationVld = TRUE;
        Packet.TrailerOperationVld = TRUE;
        TrailerType = Action.steering_entry_action_single_desc.trailer_type; //Action.TrailerType;
        Packet.TrailerType = TrailerType;
        var TrailerCommand : TrailerCommand = Action.steering_entry_action_single_desc.trailer_command.as_a(TrailerCommand);
        var TrailerSize    : int            = TrailerCommand in [InserTrailer] ? Action.steering_entry_action_single_desc.trailer_size : (-1)*Packet.PsaControlDesc.trailer_size;
        messagef(MEDIUM,"UpdateTrailer FcId=%d | TrailerType=%s TrailerCommand=%s TrailerSize=0x%x", Packet.FcId, TrailerType, TrailerCommand, TrailerSize);
        case TrailerType {
            [ipsec]: {
                messagef(MEDIUM,"IPSec Insert/Remove Trailer");
                var EspPacket      : NetworkPacket  = GetEspPacket(Packet.PsaNetworkPacket);
                case TrailerCommand {
                    InserTrailer: {
                        var PadAndCrcSize               : uint = GetPadAndCrcSizeAfterPushEspAndTrailerInsertion(Packet, TrailerSize);
                        var CurrEspPayloadSize          : uint = Packet.PsaNetworkPacket.GetPayload().size() + PadAndCrcSize; //Packet.LsoPadSize;
                        var CurrEspPayloadSizeIncTrailer: uint = CurrEspPayloadSize + TrailerSize;
                        var EspPaddingBytes             : uint = CurrEspPayloadSizeIncTrailer%4 == 0 ? 0 : 4 - CurrEspPayloadSizeIncTrailer%4;
                        Packet.EspPaddingBytes = EspPaddingBytes;
                        messagef(MEDIUM,"UpdateTrailer | FcId=%d | PayloadSize=0x%x | PaddingSize=0x%x | TrailerSize=0x%x", Packet.FcId, CurrEspPayloadSize, EspPaddingBytes, TrailerSize);
                        messagef(HIGH,"UpdateTrailer | FcId=%d | Packet Before Updates:\n", Packet.FcId) {
                            Packet.PsaNetworkPacket.PrintMe();
                        };
                        UpdateEspHeaderForTrailer(Packet, EspPacket, EspPaddingBytes, TrailerSize);
                        TrailerSize += EspPaddingBytes;
                        var EspHeaderIndex   : uint                  = Packet.PsaNetworkPacket.GetFlatHeaderList().first_index(it.HeaderKind in [ESP]);
                        var HeadersBeforeEsp : list of GeneralHeader = Packet.PsaNetworkPacket.GetFlatHeaderList()[0..EspHeaderIndex-1];
                        MarkCalculatedHeaders(Packet, HeadersBeforeEsp);
                        Packet.TrailerSize = TrailerSize;
                        Packet.ExpPacketSize += TrailerSize; // for MAC Padding
                        Packet.SetDontUnpackTrailerToFalse = TRUE; // we want to see IPSec Trailer
                        UNITS(Psa,InstanceIndex).PsaSB.UnpackAfterOffload(Packet);
                        UpdatePacketLenAndChecksumForLso(Packet, PadAndCrcSize);
                        RemoveEspTrailer(Packet);
                        compute EspPacket.Pack(FALSE);
                        Packet.ExpPacketSize -= TrailerSize;
                        Packet.SetDontUnpackTrailerToFalse = FALSE;
                        UNITS(Psa,InstanceIndex).PsaSB.UnpackPsaPacket(Packet.PsaNetworkPacket, Packet);
                        RestoreMacPaddingInTrailerInsertion(Packet);
                        compute EspPacket.Pack(FALSE);
                        Packet.PsaNetworkPacket.PacketSize += Packet.TrailerSize; // PacketSize is updated mainly in UnpackAfterOffloads() method. this value is used for PffChecks on Header Lengths. We added trailer, so we need to 'see' it in the checks.
                        messagef(HIGH,"UpdateTrailer | FcId=%d | Packet After Updates:\n", Packet.FcId) {
                            Packet.PsaNetworkPacket.PrintMe();
                        };
                    };
                    RemoveTrailer: {
                        var OuterMacPaddingSize : uint = Packet.PsaNetworkPacket.MACHeader().pad.size();
                        var AbsTrailerSize      : uint = abs(TrailerSize);
                        Packet.RxIpsecUnawareFlow.TrailerRemove                                                                    = TRUE;
                        GET_PSA_FATHER.SteeringWbVerifier.PacketsIpsecInfo.key(Packet.PsaNetworkPacket.FcId).CoverageIpsecFlowType = RxUnaware;
                        messagef(HIGH,"Before Removing Trailer PackedPacket: %s", Packet.PsaNetworkPacket.PackedPacket);
                        var PacketSize : uint = Packet.PsaNetworkPacket.PackedPacket.size();
                        UpdateEspHeaderParameters(Packet);
                        RemoveTrailerBytes(PacketSize,Packet);
                        if Action.steering_entry_action_single_desc.update_fields.as_a(bool) {
                            //                    var FcsSize : uint = Packet.FcsRemoved ? 0 : FCS_LEN;
                            Packet.ExpPacketSize -= AbsTrailerSize; //Packet.PsaControlDesc.trailer_size;
                            MarkCalculatedHeaders(Packet, Packet.AfterESPHeaders);
                            UNITS(Psa,InstanceIndex).PsaSB.UnpackAfterOffload(Packet);
                            Packet.UpdateValidData(Packet.TrailerValidBytesNumber, Remove);
                            Packet.TrailerSize = AbsTrailerSize;
                            messagef(HIGH,"After Removing Trailer PackedPacket: %s", Packet.PsaNetworkPacket.PackedPacket);
                            messagef(MEDIUM,"After Updating Packet Checksum / Lengths after Trailer Removal") {
                                Packet.PsaNetworkPacket.PrintMe();
                            };
                        };
                    };
                };
            };
            [macsec]: {
                case TrailerCommand {
                    InserTrailer: {
                        messagef(MEDIUM,"MACSec Insert Trailer");
//                        var MACSecPacket : NetworkPacket = GetMACSecPacket(Packet.PsaNetworkPacket);
                        Packet.PushMACSecTrailer = TRUE;
                        Packet.TrailerSize = TrailerSize;
//                        var MACSecHeader : MacInternalHeader = GetMACSecHeader(MACSecPacket, FALSE);
//                        Packet.ExpPacketSize += TrailerSize; // for MAC Padding. TODO - Need to use it temporarily for MAC padding. Need to add variable under ParserEntryPacket to save ICV_Assigned and DontUnpackMACSecICV, which will be set in UnpackAfterOffloads method
                        UNITS(Psa,InstanceIndex).PsaSB.UnpackAfterOffload(Packet);
                    };
                    RemoveTrailer: {
                        messagef(MEDIUM,"MACSec Remove Trailer");
                        Packet.TrailerSize = MACSEC_ICV_SIZE;
                        Packet.ExpPacketSize -= Packet.TrailerSize;
                        Packet.UpdateValidData(Packet.TrailerValidBytesNumber, Remove);
                        messagef(MEDIUM,"Packet before MACSec RemoveTrailer:") {
                            Packet.PsaNetworkPacket.PrintMe();
                        };
                        Packet.PoppedMACSecTrailer = TRUE;
                        Packet.RemovedTrailer = BusToListOfBytes(GetMACSecHeader(Packet.PsaNetworkPacket).ICV, Packet.TrailerSize);
                        MarkCalculatedHeaders(Packet);
                        UNITS(Psa,InstanceIndex).PsaSB.UnpackAfterOffload(Packet);
                        messagef(MEDIUM,"Packet after MACSec RemoveTrailer:") {
                            Packet.PsaNetworkPacket.PrintMe();
                        };
                    };
                };
            };
        };
    };

    UpdateCount(IsSource : bool, Packet : *ParserEntryPacket, Action : SteeringAction, EntryGvmi : uint(bits:16)) is {
        CountOnSourceGvmi = IsSource;
        CountOnDestGvmi   = not IsSource;
        GvmiCounterIndex  = Action.steering_entry_action_single_desc.counter_id;
    };

    UpdateCounterGvmi(Packet : ParserEntryPacket, EntryGvmi : uint(bits:16)) is {
        var EnvSlice : SteeringSlice = GET_PSA_FATHER.SteeringWbVerifier.EnvSlices[Packet.SliceId];
        CounterGvmi       = CountOnSourceGvmi ? EnvSlice.SteeringActions.SourceQpGvmi[47:32] : EntryGvmi;
    };

    GetPadAndCrcSizeAfterPushEspAndTrailerInsertion(Packet : ParserEntryPacket, TrailerSize : uint) : uint is {
        // we don't support insert trailer in PsaMode != Sx
        var ParserEntryPacket : ParserEntryPacket = Packet.copy();
        ParserEntryPacket.PsaNetworkPacket = deep_copy(Packet.PsaNetworkPacket);
        if TrailerSize > 0 { // Trailer occured
            if Packet.PushEsp {
                var Trailer : list of byte;
                Trailer.resize(TrailerSize+2);
                ParserEntryPacket.PsaNetworkPacket.GetPayload().add(Trailer);
                compute ParserEntryPacket.PsaNetworkPacket.Pack(FALSE);
            } else if Packet.PushMACSec { // no need to add trailer in MACSec since MACSec data restirction (48B) will include L2Pad to 60B
//                GetMACSecHeader(ParserEntryPacket.PsaNetworkPacket).ICV_Assigned = TRUE;
//                compute ParserEntryPacket.PsaNetworkPacket.Pack(FALSE);
            };
        };
        if Packet.Encapsulated {
            return Packet.InnerPaddingForCryptoPush;
        } else {
//            var IncludeMinimalEthPacket : bool = not Packet.Decapsulated;
            return ParserEntryPacket.GetPadAndCrcSize(TRUE,FALSE,FALSE,TRUE);
        };
    };


    RestoreMacPaddingInTrailerInsertion(Packet : ParserEntryPacket) is {
        if Packet.TunneledIPSec or Packet.Encapsulated or Packet.PsaNetworkPacket.MACHeader().pad.size() >= Packet.OriginalMacPaddingSize { return; }; // if Tunneled IPSec, we already handled MAC Padding (Padding should go to InnerPacket Payload
//        if not Packet.TunneledIPSec and Packet.PsaNetworkPacket.MACHeader().pad.size() < Packet.OriginalMacPaddingSize {
        var Payload      : list of byte = Packet.PsaNetworkPacket.GetPayload();
        var PayloadSize  : uint         = Payload.size();
        var PaddingBytes : list of byte = Payload[PayloadSize - Packet.OriginalMacPaddingSize + Packet.PsaNetworkPacket.MACHeader().pad.size()..];
        for i from 0 to Packet.OriginalMacPaddingSize-Packet.PsaNetworkPacket.MACHeader().pad.size()-1 {
            compute Payload.pop();
        };
        Packet.PsaNetworkPacket.MACHeader().pad.add(PaddingBytes);
    };

    UpdateEspHeaderParameters(ExpectedPkt : ParserEntryPacket) is {
        var Action    : SteeringNodeModificationActions = new;
        var EspHeader : GeneralHeader                   = HANDLERS(Steering).FromAnchor2Header(ExpectedPkt.PsaNetworkPacket,esp);
        if EspHeader == NULL { return};
        ExpectedPkt.ESPTrailerOffsetFromEnd = ExpectedPkt.PsaNetworkPacket.PackedPacket.size() - EspHeader.as_a(ESPHeader).PaddingOffset + ExpectedPkt.FcsRemoved.as_a(uint)*FCS_LEN; //ExpectedPkt.PsaControlDesc.trailer_size;
//        var ESPIndex : uint = ExpectedPkt.PsaNetworkPacket.GetFlatHeaderList().first_index(it.HeaderKind in [ESP,UDP]);
        var ESPIndex : uint = ExpectedPkt.PsaNetworkPacket.GetFlatHeaderList().first_index(it.HeaderKind in [ESP]);
        ExpectedPkt.AfterESPHeaders = ExpectedPkt.PsaNetworkPacket.GetFlatHeaderList()[..ESPIndex-1];
        UpdateRemovedTrailer(ExpectedPkt);
        RemoveEspTrailer(ExpectedPkt);
    };

    UpdatePacketLenAndChecksumForLso(Packet : ParserEntryPacket, PadAndCrcSize : uint) is {
        if PadAndCrcSize == 0 { return; };
        // need to update IP before ESP Header with Lso Padding of the Inner padding (as performed in offloads)
        //var IpIndex     : uint                            = Packet.PsaNetworkPacket.Headers.first_index(it.HeaderKind in [IPv4, IPv6]);
        var EspIndexM1  : uint                            = Packet.PsaNetworkPacket.Headers.first_index(it.HeaderKind in [ESP]) - 1;
        var DummyAction : SteeringNodeModificationActions = new;
        UNITS(Psa,InstanceIndex).SteeringWbVerifier.UpdateHeadersLengthFields(Packet, DummyAction, PadAndCrcSize, EspIndexM1); // update length
        UNITS(Psa,InstanceIndex).PsaSB.UnpackPsaPacket(Packet.PsaNetworkPacket,Packet);
        Packet.PsaNetworkPacket.MarkAllFieldsAlreadyCalculated();
        Packet.PsaNetworkPacket.MarkAllCRCsAlreadyCalculated();
        UNITS(Psa,InstanceIndex).SteeringWbVerifier.UpdateHeadersChecksumFields(Packet, DummyAction, PadAndCrcSize, EspIndexM1); // update checksum
        UNITS(Psa,InstanceIndex).PsaSB.UnpackAfterOffload(Packet);
    };

    UpdateEspHeaderForTrailer(Packet : ParserEntryPacket, EspPacket : NetworkPacket, EspPaddingBytes : uint, TrailerSize : uint) is {
        EspPacket.ESPHeader().Padding.resize(EspPaddingBytes);
        EspPacket.ESPHeader().NextHeader = Packet.NextHeaderRegister;
        EspPacket.ESPHeader().PadLength  = EspPacket.ESPHeader().Padding.size();
        EspPacket.ESPHeader().AuthenticationData.resize(TrailerSize-2); // PadLength + NextHeader
        EspPacket.EspAuthenticationDataLen               = TrailerSize-2;
        EspPacket.ESPHeader().AllTrailerAssigned         = TRUE;
        EspPacket.ESPHeader().AuthenticationDataAssigned = TRUE;
        Packet.DontUnpackESPAuthenticationData           = FALSE;
        Packet.DontUnpackESPPadAndNextHeader             = FALSE;

    };

    RemoveEspTrailer(ExpectedPkt : ParserEntryPacket) is {
        var EspPacket : NetworkPacket = GetEspPacket(ExpectedPkt.PsaNetworkPacket);
        EspPacket.ESPHeader().Padding.clear();
        EspPacket.ESPHeader().AuthenticationData.clear(); // PadLength + NextHeader
        EspPacket.ESPHeader().AllTrailerAssigned         = FALSE;
        EspPacket.ESPHeader().AuthenticationDataAssigned = FALSE;
        ExpectedPkt.DontUnpackESPAuthenticationData      = TRUE;
        ExpectedPkt.DontUnpackESPPadAndNextHeader        = TRUE;
    };


    RemoveTrailerBytes(PacketSize : uint, Packet : ParserEntryPacket) is {
        if GetEspPacket(Packet.PsaNetworkPacket).HasHeader(ESP) {
            // we didn't remove ESP header yet
            // we saved RemovedTrailerAlready
            messagef(HIGH,"RemovedTrailer: %s", Packet.RemovedTrailer);
        } else { // we already removed ESP Header
            var TrailerStartOffset : uint       = PacketSize - Packet.ESPTrailerOffsetFromEnd;
            var MacPaddingHeader   : MACHeaders = Packet.TunneledIPSec and Packet.PsaNetworkPacket.HasHeader(MAC) and Packet.PsaNetworkPacket.MACHeader().pad.size() > 0 ? Packet.PsaNetworkPacket.MACHeader() : NULL; // in TunneledIPSec after PopEsp we'll have MAC Padding on the outer packet
            if MacPaddingHeader == NULL and Packet.PsaNetworkPacket.InnerPacket != NULL{
                MacPaddingHeader = Packet.PsaNetworkPacket.InnerPacket.HasHeader(MAC) and Packet.PsaNetworkPacket.InnerPacket.MACHeader().pad.size() > 0 ? Packet.PsaNetworkPacket.InnerPacket.MACHeader() : NULL;
            };
            Packet.RemovedTrailer = Packet.PsaNetworkPacket.PackedPacket[TrailerStartOffset..TrailerStartOffset+Packet.PsaControlDesc.trailer_size-1];
            messagef(HIGH,"RemovedTrailer: %s", Packet.RemovedTrailer);
            if Packet.PsaNetworkPacket.Trailers is not empty {
                for Index from 0 to Packet.PsaControlDesc.trailer_size-1 {
                    Packet.PsaNetworkPacket.Trailers.first(TRUE).TrailerBytes.delete(Packet.PsaNetworkPacket.Trailers.first(TRUE).TrailerBytes.size()-1);
                };
                //Packet.PsaNetworkPacket.Trailers.clear();
            } else if MacPaddingHeader != NULL and MacPaddingHeader.pad.size() >= Packet.PsaControlDesc.trailer_size{
                for Index from 0 to Packet.PsaControlDesc.trailer_size-1 {
                    MacPaddingHeader.pad.delete(MacPaddingHeader.pad.size() - 1); //RemoveTrailer
                };
            } else if Packet.PsaNetworkPacket.HasHeader(IBTransport) and Packet.PsaNetworkPacket.Payload.size() >= Packet.PsaControlDesc.trailer_size - ICRC_LEN {
                var IcrcPosition : uint = Packet.PsaNetworkPacket.Payload.size()-Packet.PsaControlDesc.trailer_size;
                Packet.PsaNetworkPacket.IBTransportHeader().ICRC = ListOfBytesToBus(Packet.PsaNetworkPacket.Payload[IcrcPosition..IcrcPosition+ICRC_LEN-1],4);
                for Index from 0 to Packet.PsaControlDesc.trailer_size-1 {
                    Packet.PsaNetworkPacket.Payload.delete(Packet.PsaNetworkPacket.Payload.size() - 1); //RemoveTrailer
                };
            } else if Packet.PsaNetworkPacket.Payload.size() >= Packet.PsaControlDesc.trailer_size{
                for Index from 0 to Packet.PsaControlDesc.trailer_size-1 {
                    Packet.PsaNetworkPacket.Payload.delete(Packet.PsaNetworkPacket.Payload.size() - 1); //RemoveTrailer
                };
            };
        };
    };

    UpdateRemovedTrailer(ExpectedPkt : ParserEntryPacket) is {
        var EspHeader : ESPHeader = GetEspPacket(ExpectedPkt.PsaNetworkPacket).ESPHeader();
        ExpectedPkt.RemovedTrailer = {EspHeader.Padding; EspHeader.PadLength; EspHeader.NextHeader; EspHeader.AuthenticationData;};
    };

    MarkCalculatedHeaders(Packet : ParserEntryPacket, HeadersToUpdate : list of GeneralHeader = {}) is {
        var CalcPacket : NetworkPacket = Packet.PsaNetworkPacket;
        CalcPacket.MarkAllFieldsAlreadyCalculated();
        CalcPacket.MarkAllCRCsAlreadyCalculated();
//        var Headers : list of GeneralHeader = HeadersToUpdate.is_empty() ? Packet.AfterESPHeaders : HeadersToUpdate;
        for each (Header) in HeadersToUpdate {
            messagef(HIGH,"Header to calculate : %s",Header.HeaderKind);
            case(Header.HeaderKind){
                IPv4 : {
                    if CalcPacket.HasHeader(IPv4){
                        CalcPacket.IPv4Header().CalculatedAlready         = FALSE;
                        CalcPacket.IPv4Header().CalculatedChecksumAlready = FALSE;
                    };
                };
                IPv6 : {
                    if CalcPacket.HasHeader(IPv6){
                        CalcPacket.IPv6Header().CalculatedAlready = FALSE;
                    };
                };
                TCP : {
                    if CalcPacket.HasHeader(TCP){
                        CalcPacket.TCPHeader().CalculatedChecksumAlready = FALSE;
                    };
                };
                UDP : {
                    if CalcPacket.HasHeader(UDP){
                        CalcPacket.UDPHeader().CalculatedAlready = FALSE;
                        if CalcPacket.UDPHeader().Checksum != 0 {
                            CalcPacket.UDPHeader().CalculatedChecksumAlready = FALSE;
                        };
                    };
                };
            };
        };
    };

    UpdateModifyList(ExpectedPkt : *ParserEntryPacket, Action : SteeringAction, EntryGvmi : uint(bits : 16)) is {
//        var ActionListUintData            : list of uint                            = GetActionsAsData(ExpectedPkt,Action,EntryGvmi);
        var RxSxType                      : RxSxType                                = (ExpectedPkt.PsaControlDesc.packet_source in [sx]) ? SX : RX;
        var CalculatedModificationActions : list of SteeringNodeModificationActions = TransformSteeringActionToSteeringNodeModificationActions(ExpectedPkt, Action, EntryGvmi);
        SavePacketBeforeActions(ExpectedPkt,CalculatedModificationActions);
        CollectVniToCqeCrossActions(CalculatedModificationActions, RxSxType, Action);
        messagef(HIGH,"LogParser Start, FcId=%d.",ExpectedPkt.FcId);
        for each (ModifyAction) in CalculatedModificationActions{            
            MarkIPSecUnawareFlowActions(ExpectedPkt, ModifyAction);
            ModifyAction(ExpectedPkt, ModifyAction, RxSxType, EntryGvmi);
            ActionMarkHeaderWasChanged(ExpectedPkt,ModifyAction,RxSxType);
        };
        messagef(HIGH,"LogParser End, FcId=%d.",ExpectedPkt.FcId)
    };
           
    TransformSteeringActionToSteeringNodeModificationActions(ExpectedPkt : *ParserEntryPacket, Action : SteeringAction, EntryGvmi : uint(bits : 16)) : list of SteeringNodeModificationActions is {
        var ActionListUintData : list of uint = GetActionsAsData(ExpectedPkt,Action,EntryGvmi);
        var RxSxType           : RxSxType     = (ExpectedPkt.PsaControlDesc.packet_source in [sx]) ? SX : RX;
        result                                = UnpackModificationList(ActionListUintData,RxSxType);        
    };
                                                                                                                                                                                                             
    CollectVniToCqeCrossActions(CalculatedModificationActions : list of SteeringNodeModificationActions, RxSxType : RxSxType, Action : SteeringAction) is {
        var ModificationActions : list of SteeringNodeActionType = RxSxType==RX ? CalculatedModificationActions.RxModificationActionType : CalculatedModificationActions.SxModificationActionType;
        var RemoveHeadersIndex : uint = ModificationActions.first_index(it == RemoveHeaderToHeader);
        if RemoveHeadersIndex == UNDEF { return; };
        var VniToCqe   : bool = CalculatedModificationActions[RemoveHeadersIndex].VniToCqe==1;
        if not VniToCqe { return; };
        var HasCopyAction : bool = ModificationActions.has(it == Copy);
        var HasAddAction  : bool = ModificationActions.has(it == Add);
        var HasSetAction  : bool = ModificationActions.has(it == Set);
        if HasCopyAction { GET_PSA_FATHER.SteeringWbVerifier.RmHeadersVniCopyFlag = TRUE; };
        if HasAddAction  { GET_PSA_FATHER.SteeringWbVerifier.RmHeadersVniSetFlag  = TRUE; };
        if HasSetAction  { GET_PSA_FATHER.SteeringWbVerifier.RmHeadersVniAddFlag  = TRUE; };
    };
                                                                                                                                                                                                             
    MarkIPSecUnawareFlowActions(ExpectedPkt : ParserEntryPacket, ModifyAction : SteeringNodeModificationActions) is {
        var RegisterDwOffset : list of SteeringDWDefinerFields = {SteeringRegister0_63_32; SteeringRegister0_31_0; SteeringRegister1_63_32; SteeringRegister1_31_0; SteeringRegister2_63_32; SteeringRegister2_31_0;
                                                                  SteeringRegister3_63_32; SteeringRegister3_31_0; SteeringRegister4_63_32; SteeringRegister4_31_0; SteeringRegister5_63_32; SteeringRegister5_31_0};
    };

    GetActionsAsData(ExpectedPkt : *ParserEntryPacket, Action : SteeringAction, EntryGvmi : uint(bits : 16)) : list of uint is{
        case (Action.ActionId) {
            [add,set,copy,insert_inline,insert_pointer] : {
                var ActionListData : list of byte = BusToListOfBytes(Action.steering_entry_action_double_desc.Pack(),STEERING_ENTRY_ACTION_DOUBLE_DESC_PACK_SIZE/8);
                result = BusToListOfUint(ListOfBytesToBus(ActionListData,8), 2);
            };
            [remove_by_size,remove_headers] : {
                var ActionListData : list of byte = BusToListOfBytes(Action.steering_entry_action_single_desc.Pack(),STEERING_ENTRY_ACTION_SINGLE_DESC_PACK_SIZE/8);
                result = BusToListOfUint(ListOfBytesToBus(ActionListData,4),1);
                result.add(0);
            };
            modify_list : {

                var ActionPointer             : uint(bits : STEERING_ENTRY_ACTION_SINGLE_DESC_MODIFY_ACTION_POINTER_WIDTH) = Action.steering_entry_action_single_desc.modify_action_pointer;
                var NumOfActions              : uint(bits:8)                                                               = Action.steering_entry_action_single_desc.num_of_modify_actions;
                var ModificationActionAddress : uint(bits:64)                                                              = HANDLERS(Mem).Icm.IndexToIcmVa(EntryGvmi,SteeringModificationActionList,ActionPointer);
                var ActionListData            : list of byte                                                               = HANDLERS(Mem).Icm.ReadIcmVa(EntryGvmi,SteeringModificationActionList,ModificationActionAddress,NumOfActions*8);
                result = BusToListOfUint(ListOfBytesToBus(ActionListData,NumOfActions*8), NumOfActions*2);
            };
            accelerated_list : {
                var ModifyPatternPointer   : uint(bits : STEERING_ENTRY_ACTION_DOUBLE_DESC_MODIFY_PATTERN_POINTER_WIDTH)  = Action.steering_entry_action_double_desc.modify_pattern_pointer;
                var ModifyArgumentPointer  : uint(bits : STEERING_ENTRY_ACTION_DOUBLE_DESC_MODIFY_ARGUMENT_POINTER_WIDTH) = Action.steering_entry_action_double_desc.modify_argument_pointer;
                var NumOfActions           : uint(bits : STEERING_ENTRY_ACTION_DOUBLE_DESC_NUM_OF_MODIFY_ACTIONS_WIDTH)   = Action.steering_entry_action_double_desc.num_of_modify_actions;
                var ModifyPatternAddress   : uint(bits:64)                                                                = HANDLERS(Mem).Icm.IndexToIcmVa(EntryGvmi,SteeringModificationPatternList,ModifyPatternPointer);
                var ModifyArgumentAddress  : uint(bits:64)                                                                = HANDLERS(Mem).Icm.IndexToIcmVa(EntryGvmi,GtaModificationArgumentsContext,ModifyArgumentPointer);
                var ModifyPatternListData  : list of byte                                                                 = HANDLERS(Mem).Icm.ReadIcmVa(EntryGvmi,SteeringModificationPatternList,ModifyPatternAddress,NumOfActions*8);
                var ModifyArgumentListData : list of byte                                                                 = HANDLERS(Mem).Icm.ReadIcmVa(EntryGvmi,GtaModificationArgumentsContext,ModifyArgumentAddress,NumOfActions*8);
                var ActionListData         : list of byte                                                                 = GetActionListDataFromPatternAndArgument(ExpectedPkt,ModifyPatternListData,ModifyArgumentListData);
                result = BusToListOfUint(ListOfBytesToBus(ActionListData,NumOfActions*8), NumOfActions*2);
            };
            default : { DUTError(202,"Unknown action id = %s",Action.ActionId)};
        };
    };

    GetActionListDataFromPatternAndArgument(ExpectedPkt : *ParserEntryPacket , ModifyPatternListData : list of byte , ModifyArgumentListData : list of byte) : list of byte is {
        var RxSxType           : RxSxType              = (ExpectedPkt.PsaControlDesc.packet_source in [sx]) ? SX : RX;
        var ModifyPatternList  : list of uint(bits:64) = ListOfByteToListOf64Bits(ModifyPatternListData);
        var ModifyArgumentList : list of uint(bits:64) = ListOfByteToListOf64Bits(ModifyArgumentListData);
        var MergedModifyList   : list of uint(bits:64);
        for ActionNumber from 0 to ModifyPatternList.size() - 1 {
            var ModifyPattern              : uint(bits:64)                   = ModifyPatternList[ActionNumber];
            var ModifyArgument             : uint(bits:64)                   = ModifyArgumentList[ActionNumber];
            var SteeringModificationAction : SteeringNodeModificationActions = new;
            SteeringModificationAction.Unpack(ModifyPattern,RxSxType);
            var ModificationActionType : SteeringNodeActionType = RxSxType == RX ? SteeringModificationAction.RxModificationActionType : SteeringModificationAction.SxModificationActionType;
            var PatternMask            : uint(bits:64)          = HANDLERS(Steering).GetActionPatternMask(ModificationActionType);
            var MergedAction           : uint(bits:64)          = PatternMask & ModifyPattern | ~PatternMask & ModifyArgument;
            messagef(HIGH,"GetActionListDataFromPatternAndArgument | FcId=%d | ActionNumber = %d/%d:",ExpectedPkt.FcId,ActionNumber+1,ModifyPatternList.size());
            messagef(HIGH,"ActionType     = %s",ModificationActionType);
            messagef(HIGH,"ModifyPattern  = %s",ModifyPattern);
            messagef(HIGH,"ModifyArgument = %s",ModifyArgument);
            messagef(HIGH,"PatternMask    = %s",PatternMask);
            messagef(HIGH,"MergedAction   = %s",MergedAction);
            if (~PatternMask & ModifyPattern) != 0 {
                DUTError(250,"GetActionListDataFromPatternAndArgument | FcId=%d | sanity check | ~PatternMask & ModifyPattern (%s) != 0",ExpectedPkt.FcId,~PatternMask & ModifyPattern);
            };
            MergedModifyList.add(MergedAction);
        };
        result = ListOf64BitsToListOfByte(MergedModifyList);
    };

    ListOfByteToListOf64Bits(ListOfBytes : list of byte) : list of uint(bits:64) is {
        if ListOfBytes.size() % 8 != 0 {
            DUTError(300,"ListOfByteToListOf64Bits | ListOfBytes size (%d) is not divided by 8",ListOfBytes.size());
        };
        var ListOfUint     : list of uint = BusToListOfUint(ListOfBytesToBus(ListOfBytes,ListOfBytes.size()),ListOfBytes.size()/4);
        var NumberOf64Bits : uint         = ListOfUint.size() / 2;
        for i from 0 to NumberOf64Bits - 1 {
            var DataAs64Bits : uint(bits:64);
            for DwNumber from 0 to 1 {
                var StartBit : uint = (1 - DwNumber) * 32;
                DataAs64Bits[StartBit + 31 : StartBit] = ListOfUint[2 * i + DwNumber];
            };
            result.add(DataAs64Bits);
        };
        messagef(HIGH,"ListOfByteToListOf64Bits | ListOfBytes = %s | ListOf64Bits = %s",ListOfBytes,result);
    };

    ListOf64BitsToListOfByte(ListOf64Bits : list of uint(bits:64)) : list of byte is {
        for each in ListOf64Bits {
            for i from 0 to 7 {
                var StartBit : uint = (7-i) * 8;
                result.add(it[StartBit + 7 : StartBit]);
            };
        };
        messagef(HIGH,"ListOf64BitsToListOfByte | ListOf64Bits = %s | ListOfByte = %s",ListOf64Bits,result);
    };

    UnpackModificationList(ActionListUintData : list of uint,RxSxType : RxSxType) : list of SteeringNodeModificationActions is {
        ActionsHappendInSameList=0;
        for i from 0 to ActionListUintData.size()-1 {
            if (i%2 == 1) {
                continue; //ActionListUintData is a list of uint(32bit) while the data is 64bit.
            };
            var ActionData : uint(bits:64);
            ActionData[63:32] = ActionListUintData[i];
            ActionData[31:0]  = ActionListUintData[i+1];
            var SteeringModificationAction : SteeringNodeModificationActions = new;
            SteeringModificationAction.Unpack(ActionData, RxSxType);
            SteeringModificationAction.NextHeaderRegisterExist = TRUE;
            result.add(SteeringModificationAction);
            -- add coverage here.
            ModifyActionIdInList = ActionData[63:56].as_a(steering_entry_action_id_enum);
            if(ModifyActionIdInList!=nop){
                ActionsHappendInSameList[ModifyActionIdInList.as_a(uint)-STEERING_ENTRY_ACTION_ID_ENUM__COPY:ModifyActionIdInList.as_a(uint)-STEERING_ENTRY_ACTION_ID_ENUM__COPY]=1;
            }else{
                ActionsHappendInSameList[7:7]=1;
            };
            emit NonNopActionInList;
            if(RxSxType==RX){
                CollectModificationAction(SteeringModificationAction.RxModificationActionType);
            }else{
                CollectModificationAction(SteeringModificationAction.SxModificationActionType);
            };
            messagef(HIGH,appendf("Got new ModificationAction")) {
                SteeringModificationAction.PrintMe(RxSxType);
            };
        };
        emit ActionsInModifyList;
        result = result.all(RxSxType == RX ? it.RxModificationActionType not in [None] : it.SxModificationActionType not in [None]);
    };

    SavePacketBeforeActions(ExpectedPkt : *ParserEntryPacket,Actions : list of SteeringNodeModificationActions) is {
        if Actions.has(ExpectedPkt.PsaControlDesc.packet_source in [sx] ? it.SxModificationActionType in [InsertWithInline,InsertWithPointer,RemoveBySize,RemoveHeaderToHeader] : it.RxModificationActionType in [InsertWithInline,InsertWithPointer,RemoveBySize,RemoveHeaderToHeader]){
            ExpectedPkt.BeforeActionsPacket = deep_copy(ExpectedPkt.PsaNetworkPacket);
        };
    };

    IsCorrectFlexHeader(FlexHeader : SWParseDummyHeader,DwSampleIndex : uint) : bool is {
        var HeaderIndex : uint = str_sub(FlexHeader.HeaderKind.to_string(),10,1).as_a(uint);
        if CrPsaPrefix.CRREG(CR_PARSER.flex_parser[HeaderIndex].father.father_sample_vld).data[DwSampleIndex:DwSampleIndex] == 1 {
            return TRUE;
        };
        var SonMask : uint = CrPsaPrefix.CRREG(CR_PARSER.flex_parser[HeaderIndex].son.son_type_mask).data;
        var SonType : uint = CrPsaPrefix.CRREG(CR_PARSER.dw_sample[DwSampleIndex].son_type).data;
        for each (Option) in FlexHeader.FlexParsingItem.FlexOptions {
            if (Option & SonMask) == SonType {
                return TRUE;
            };
        };
    };

    UpdateFlexActionFields(ExpectedPkt : *ParserEntryPacket, Action : SteeringNodeModificationActions) is {
        if Action.DstDwOffset not in [FLEX_PARSER_DEFINER_FIELDS] and Action.SrcDwOffset not in [FLEX_PARSER_DEFINER_FIELDS]{return};
        Action.FlexSampledDw    = ExpectedPkt.PffChecks.SampledDw;
        Action.FlexSampleOffset = ExpectedPkt.PffChecks.SampleOffset;
        var Index : uint = 0;
        case (Action.DstDwOffset){
            FlexParser0: {Index = 0};
            FlexParser1: {Index = 1};
            FlexParser2: {Index = 2};
            FlexParser3: {Index = 3};
            FlexParser4: {Index = 4};
            FlexParser5: {Index = 5};
            FlexParser6: {Index = 6};
            FlexParser7: {Index = 7};
        };
        Action.FlexHeaderInPacket = ExpectedPkt.PffChecks.FlexSampleHeader[Index].as_a(SWParseDummyHeader);
    };

    ModifyAction(ExpectedPkt : *ParserEntryPacket, Action : SteeringNodeModificationActions, RxSxType : RxSxType, EntryGvmi : uint(bits : 16)) is {
        var PacketToModify : NetworkPacket = ExpectedPkt.PsaNetworkPacket;
        var ModificationActionType : SteeringNodeActionType;
        var EnvSlice : SteeringSlice = UNITS(Psa, InstanceIndex).SteeringWbVerifier.EnvSlices[ExpectedPkt.SliceId];
        ModificationActionType = RxSxType == RX ? Action.RxModificationActionType : Action.SxModificationActionType;
        if PacketToModify.TunnelType == IPoIB {
            if PacketToModify.InnerPacket != NULL {
                Action.OnInnerPacket = TRUE;
            };
        };
        if (Action.DstDwOffset in [FLEX_PARSER_DEFINER_FIELDS] or Action.SrcDwOffset in [FLEX_PARSER_DEFINER_FIELDS]) {
            UpdateFlexActionFields(ExpectedPkt,Action);
        };
        if EnvSlice.PffResults.first_l4_exist == 0 { 
            Action.DontUpdateL4Checksum = TRUE; 
        };
        ExpectedPkt.UpdateESPFlags();
        case (ModificationActionType) {
            [Add,Set,Copy]: {
                if Action.DstDwOffset in [OuterDmac_15_0] and Action.DstLsbOffset == 0 { // Ethertype
                    PushPopActionList.add(Action);
                    return;
                };
                if Action.CheckMetaDataDwOffset(Action.DstDwOffset) or Action.CheckMetaDataDwOffset(Action.SrcDwOffset){
                    UpdateActionMetaData(ExpectedPkt,Action,%{Action.DstDwOffset,Action.SrcDwOffset});
                };
                var OldChecksumRewriteEnable : bool = ChecksumRewriteEnable;
                if Action.DstDwOffset in [OuterIp_NextHeader] {
                    if Action.DstLsbOffset < 8{
                        ExpectedPkt.RewriteOnNextHeader = TRUE;
                        ExpectedPkt.UpdateESPFlags();
                    };
                };
                if Action.OnInnerPacket {
                    Action.ApplyAction(PacketToModify.InnerPacket,ModificationActionType,ChecksumRewriteEnable);
                } else {
                    Action.ApplyAction(PacketToModify,ModificationActionType,ChecksumRewriteEnable);
                };
                ChecksumRewriteEnable = OldChecksumRewriteEnable;
                if Action.CheckMetaDataDwOffset(Action.DstDwOffset){
                    UpdateMetaDataFromAction(ExpectedPkt,Action,Action.DstDwOffset);
                };
                if Action.DstDwOffset in [FLEX_PARSER_DEFINER_FIELDS] {
                    UpdateFlexDataFromAction(ExpectedPkt,Action);
                };
                if Action.CheckOuterEcnDwOffset() {
                      GET_PSA_FATHER.SteeringWbVerifier.MarkEcnOk(ExpectedPkt, ecn_rewrite);
                };
                GET_PSA_FATHER.SteeringWbVerifier.SteeringModifyTypeCov.TypeOccured(Action.DstDwOffset);
            };
            InsertWithInline: {
                Action.DataToPush = BusToListOfBytes(Action.InlineData, 4);
                messagef(MEDIUM,"LogParser Modify Action : %s\n",ModificationActionType) {
                    Action.PrintMe(RX);
                };
                PushPopActionList.add(Action);
            };
            InsertWithPointer: {
                Action.DataToPush = CollectDataToPush(Action, EntryGvmi);
                messagef(MEDIUM,"LogParser Modify Action : %s\n",ModificationActionType) {
                    Action.PrintMe(RX);
                };
                PushPopActionList.add(Action);
            };
            [RemoveBySize, RemoveHeaderToHeader]: {
                //Headers are valid only after reparse.
                //At steering done Modified headers size and pkt length should be calculated using these actions.
                messagef(MEDIUM,"LogParser Modify Action : %s\n",ModificationActionType) {
                    Action.PrintMe(RX);
                };
                PushPopActionList.add(Action);
                MetaDataToCQEVld = Action.VniToCqe == 1 ? TRUE : MetaDataToCQEVld;
            };
            default : {DUTError(100,"unknown action type %s",ModificationActionType)};
        };
    };
    UpdateFlexDataFromAction(ExpectedPkt : *ParserEntryPacket, Action : SteeringNodeModificationActions) is {
        var EnvSlice : SteeringSlice = UNITS(Psa, InstanceIndex).SteeringWbVerifier.EnvSlices[ExpectedPkt.SliceId];
        EnvSlice.PffResults.SampledDw = Action.FlexSampledDw;

        var FlexIndex : uint = str_sub(Action.FlexHeaderInPacket.HeaderKind.to_string(),10,1).as_a(uint);
        if CrPsaPrefix.CRREG(CR_MODIFICATIONS_PIPE.appendf("flex_parser%d_update_l4_checksum_on_rewrite",FlexIndex)).data == 0 {
            messagef(HIGH,"FcId=%d, Adding DW=0x%x to DataBeforeFlexRewriteForL4CS",ExpectedPkt.PsaNetworkPacket.FcId,Action.FlexRewriteOriginalDw);
            ExpectedPkt.DataBeforeFlexRewriteForL4CS.add(BusToListOfBytes(Action.FlexRewriteOriginalDw,4));
            messagef(HIGH,"FcId=%d, Adding DW=0x%x to DataAfterFlexRewriteForL4CS",ExpectedPkt.PsaNetworkPacket.FcId,Action.FlexRewriteUpdatedDw);
            messagef(HIGH,"FcId=%d, Adding DW=0x%x to DataInvertedAfterFlexRewriteForL4CS",ExpectedPkt.PsaNetworkPacket.FcId,~Action.FlexRewriteUpdatedDw);
            ExpectedPkt.DataInvertedAfterFlexRewriteForL4CS.add(BusToListOfBytes(~Action.FlexRewriteUpdatedDw,4));
        };
    };

    UpdateActionMetaData(ExpectedPkt : *ParserEntryPacket, Action : SteeringNodeModificationActions,FieldCodes : list of SteeringDWDefinerFields) is {
        for each (FieldCode) in FieldCodes{
            case(FieldCode){
                [SteeringRegister0_31_0,SteeringRegister0_63_32] : {Action.SteeringRegister0         = SteeringRegister0};
                [SteeringRegister1_31_0,SteeringRegister1_63_32] : {Action.SteeringRegister1         = SteeringRegister1};
                [SteeringRegister2_31_0,SteeringRegister2_63_32] : {Action.SteeringRegister2         = SteeringRegister2};
                [SteeringRegister3_31_0,SteeringRegister3_63_32] : {Action.SteeringRegister3         = SteeringRegister3};
                [SteeringRegister4_31_0,SteeringRegister4_63_32] : {Action.SteeringRegister4         = SteeringRegister4};
                [SteeringRegister5_31_0,SteeringRegister5_63_32] : {Action.SteeringRegister5         = SteeringRegister5};
                GeneralPurposeLookupField                        : {Action.GeneralPurposeLookupField = ExpectedPkt.GeneralPurposeLookupField};
                MetaData                                         : {Action.MetaDataForCQE            = MetaDataForCQE;};
                IPSec_Syndrome_NextHeader                        : {Action.NextHeaderRegister        = ExpectedPkt.NextHeaderRegister};
                [SourceQpGvmi_63_32,SourceQpGvmi_31_0]           : {Action.SourceQpGvmi              = SourceQpGvmi};
                HdsAnchorOffst                                   : {
                    Action.HdsAnchor = HeaderSplitAnchor;
                    Action.HdsOffst  = HeaderSplitOffset;
            };
        };
    };
    };

    UpdateMetaDataFromAction(ExpectedPkt : *ParserEntryPacket, Action : SteeringNodeModificationActions,DstFieldCode : SteeringDWDefinerFields) is {
        case(DstFieldCode){
            [SteeringRegister0_31_0,SteeringRegister0_63_32] : {SteeringRegister0                     = Action.SteeringRegister0};
            [SteeringRegister1_31_0,SteeringRegister1_63_32] : {SteeringRegister1                     = Action.SteeringRegister1};
            [SteeringRegister2_31_0,SteeringRegister2_63_32] : {SteeringRegister2                     = Action.SteeringRegister2};
            [SteeringRegister3_31_0,SteeringRegister3_63_32] : {SteeringRegister3                     = Action.SteeringRegister3};
            [SteeringRegister4_31_0,SteeringRegister4_63_32] : {SteeringRegister4                     = Action.SteeringRegister4};
            [SteeringRegister5_31_0,SteeringRegister5_63_32] : {SteeringRegister5                     = Action.SteeringRegister5};
            GeneralPurposeLookupField                        : {ExpectedPkt.GeneralPurposeLookupField = Action.GeneralPurposeLookupField};
            IPSec_Syndrome_NextHeader                        : {ExpectedPkt.NextHeaderRegister        = Action.NextHeaderRegister};
            [SourceQpGvmi_63_32,SourceQpGvmi_31_0]           : {SourceQpGvmi                          = Action.SourceQpGvmi};
            HdsAnchorOffst                                   : {
                HeaderSplitAnchor = Action.HdsAnchor;
                HeaderSplitOffset = Action.HdsOffst;
            };
            MetaData                                         : {
                MetaDataToCQEVld = TRUE;
                MetaDataForCQE   = Action.MetaDataForCQE;

//                 if(Action.VniToCqe==1){//Added by kayan 4 coverage
//                     var RxSxType : RxSxType= (ExpectedPkt.PsaControlDesc.packet_source in [sx]) ? SX: RX;
//                     var ModificationActionType : SteeringNodeActionType = RxSxType == RX ? Action.RxModificationActionType   : Action.SxModificationActionType;
//                     case ModificationActionType{
//                         Copy:{GET_PSA_FATHER.SteeringWbVerifier.RmHeadersVniCopyFlag =TRUE;};
//                         Set :{GET_PSA_FATHER.SteeringWbVerifier.RmHeadersVniSetFlag  =TRUE;};
//                         Add :{GET_PSA_FATHER.SteeringWbVerifier.RmHeadersVniAddFlag  =TRUE;};
//                     };
//                 };
            };
        };
    };

    ActionMarkHeaderWasChanged(ExpectedPkt : ParserEntryPacket, Action : SteeringNodeModificationActions,RxSxType : RxSxType) is {
        var ModificationActionType : SteeringNodeActionType = RxSxType == RX ? Action.RxModificationActionType : Action.SxModificationActionType;
        case (ModificationActionType){
            [Add,Copy,Set] : {
                MarkChangedHeaders(ExpectedPkt,Action,ModificationActionType);
            };
            [InsertWithInline,InsertWithPointer,
                RemoveBySize, RemoveHeaderToHeader] : {

            };
            default : {DUTError(121,"Unknwon ModificationActionType = %s",ModificationActionType)};
        };
    };

    MarkChangedHeaders(ExpectedPkt : ParserEntryPacket, Action : SteeringNodeModificationActions,ModificationActionType : SteeringNodeActionType) is {
        var PacketToModify  : NetworkPacket           = ExpectedPkt.PsaNetworkPacket;
        var HeaderProtocols : list of NetworkProtocol = Action.DwOffsetToHeader(Action.DstDwOffset);
        var Packet          : NetworkPacket           = Action.OnInnerPacket ? PacketToModify.InnerPacket : PacketToModify;
        var L4Exist         : bool                    = ExpectedPkt.PffChecks.first_l4_exist == 1;
        if Action.CheckMetaDataDwOffset(Action.DstDwOffset){return};
        if RewriteOnIPPseudoHeader(Action,ModificationActionType){
            if L4Exist and Packet.HasHeader(TCP) {HeaderProtocols.add(TCP)};
            if L4Exist and Packet.HasHeader(UDP) and Packet.UDPHeader().Checksum != 0{HeaderProtocols.add(UDP)};
        };
        for each (HeaderKind) in HeaderProtocols{
            case(Action.DstDwOffset){
                [VlANID_STEERING_DEFINER_FIELDS] : {
                    var Index    : uint                      = GetIndexByDwOffset(Action.DstDwOffset);
                    var VlanList : list of MacInternalHeader = Packet.MACHeader().MacInternalHeaders is not empty ? Packet.MACHeader().MacInternalHeaders.all(it.HeaderType == Vlan) : {};
                    if Action.DstLsbOffset <= 15 and VlanList.size() > Index{
                        ExpectedPkt.UpdateModifiedHeadersSize(VlanList[Index]);
                    };
                };
                [MACSEC_DEFINER_FIELDS] : {
                    if HasMACSecHeader(Packet) {
                        ExpectedPkt.UpdateModifiedHeadersSize(GetMACSecHeader(Packet));
                    };
                };
                [MPLS_DEFINER_FIELDS] : {
                    var Index : uint = GetIndexByDwOffset(Action.DstDwOffset);
                    if Packet.MPLSHeader().MPLSLabelStackList.size() > Index {
                        ExpectedPkt.UpdateModifiedHeadersSize(NULL,Modify,Packet.MPLSHeader().HeaderOffset,(Index + 1)* MPLS_LEN);
                    };
                };
                [OUTER_CONFIGURABLE_HEADER_0] : {
                    var ConfigurableHeader : MacInternalHeader = Packet.MACHeader().MacInternalHeaders is not empty ? Packet.MACHeader().MacInternalHeaders.first(it.HeaderType in [ConfigurableHeader1]) : NULL;
                    ExpectedPkt.UpdateModifiedHeadersSize(ConfigurableHeader);
                };
                [OUTER_CONFIGURABLE_HEADER_1] : {
                    var ConfigurableHeader : MacInternalHeader = Packet.MACHeader().MacInternalHeaders is not empty ? Packet.MACHeader().MacInternalHeaders.first(it.HeaderType in [ConfigurableHeader2]) : NULL;
                    ExpectedPkt.UpdateModifiedHeadersSize(ConfigurableHeader);
                };
                [FLEX_PARSER_DEFINER_FIELDS] : {
                    var Index : uint = GetIndexByDwOffset(Action.DstDwOffset);
                    ExpectedPkt.UpdateModifiedHeadersSize(NULL, Modify, Action.FlexHeaderInPacket.HeaderOffset + Action.FlexSampleOffset[Index],FLEX_SAMPLE_SIZE);
                };
                default :{
                    if Packet.GetFirstHeader(HeaderKind, FALSE) != NULL{
                        ExpectedPkt.UpdateModifiedHeadersSize(Packet.GetFirstHeader(HeaderKind, FALSE));
                    };
                };
            };
        };
    };

    RewriteOnIPPseudoHeader(Action : SteeringNodeModificationActions,ModificationActionType : SteeringNodeActionType) : bool is {
        if ModificationActionType not in [Add,Copy,Set]{return FALSE};
        case(Action.DstDwOffset){
            default : {return FALSE};
            [OuterIpv4_SourceAddress, OuterIpv4_DestinationAddress,
                OuterIpv6_DestinationAddress_127_96,OuterIpv6_DestinationAddress_95_64,OuterIpv6_DestinationAddress_63_32,OuterIpv6_DestinationAddress_31_0,
                OuterIpv6_SourceAddress_127_96,OuterIpv6_SourceAddress_95_64,OuterIpv6_SourceAddress_63_32,OuterIpv6_SourceAddress_31_0
            ] : {return TRUE};

        };

    };

    GetIndexByDwOffset(DwOffset : SteeringDWDefinerFields) : uint is {
        case(DwOffset){
            [InnerEthL2_FirstVlanId_11_0,OuterEthL2_FirstVlanId_11_0]   : {return 0};
            [InnerEthL2_SecondVlanId_11_0,OuterEthL2_SecondVlanId_11_0] : {return 1};
            [OuterMpls0_Label,InnerMpls0_Label]                         : {return 0};
            [OuterMpls1_Label,InnerMpls1_Label]                         : {return 1};
            [OuterMpls2_Label,InnerMpls2_Label]                         : {return 2};
            [OuterMpls3_Label,InnerMpls3_Label]                         : {return 3};
            [OuterMpls4_Label,InnerMpls4_Label]                         : {return 4};
            [FlexParser0]                                               : {return 0};
            [FlexParser1]                                               : {return 1};
            [FlexParser2]                                               : {return 2};
            [FlexParser3]                                               : {return 3};
            [FlexParser4]                                               : {return 4};
            [FlexParser5]                                               : {return 5};
            [FlexParser6]                                               : {return 6};
            [FlexParser7]                                               : {return 7};
            default                                                     : {DUTError(1919,"Unknown type")};
        };
    };

    CollectDataToPush(Action :SteeringNodeModificationActions, EntryGvmi : uint(bits : 16) = 0):list of byte is {
        var EncapPacketListVa : uint(bits : 64) = HANDLERS(Mem).Icm.IndexToIcmVa(EntryGvmi,EncapHeaders,Action.PointerForDataToPush);
        var ActionListData    : list of byte    = HANDLERS(Mem).Icm.ReadIcmVa(EntryGvmi,EncapHeaders,EncapPacketListVa,Action.SizeOfDataToPush*2);
        return ActionListData;
    };

    GetHeaderIndexByOffset(Packet : NetworkPacket, Offset : uint) : int is {
        result = Packet.Headers.first_index(it.HeaderOffset >= Offset);
    };

    UpdateAso(PsaPacket : ParserEntryPacket,SE : SteeringEntry,EntryGvmi : uint(bits : 16),Action : SteeringAction) is {
        var EnvSlice  : SteeringSlice = UNITS(Psa, InstanceIndex).SteeringWbVerifier.EnvSlices[PsaPacket.SliceId];
        var Packet    : NetworkPacket = PsaPacket.PsaNetworkPacket;
        var EthPacket : NetworkPacket = GetEthPacket(Packet);
        var EspPacket : NetworkPacket = GetEspPacket(EthPacket);
        var DoubleAction : steering_entry_action_double_desc = Action.steering_entry_action_double_desc;
        Aso                                        = new;
        Aso.FcId                                   = Packet.FcId;
        Aso.FcIdValid                              = Packet.FcIdValid;
        Aso.aso_context_type                       = DoubleAction.aso_context_type.as_a(aso_context_type_enum);
        Aso.gvmi                                   = EntryGvmi;
        Aso.aso_fields                             = DoubleAction.aso_fields;
        Aso.context_id                             = DoubleAction.aso_context_number;
        Aso.steering_reg_id          = %{DoubleAction.dest_reg_id_msb,DoubleAction.dest_reg_id};
        Aso.steering_iteration_level = PsaPacket.IterationLevel;
        EnvSlice.SteeringActions.AsoChangeOrdering = DoubleAction.change_ordering_tag;
        if (Aso.aso_context_type in [ipsec,macsec]) {
            var RandomNumber : uint;
            gen RandomNumber;
            if Aso.aso_context_type == ipsec {
                Aso.crypto_sequence_number = PsaPacket.PsaControlDesc.packet_source not in [sx] ? %{PsaPacket.PsaControlDesc.crypto_sequence_number_high, EspPacket.ESPHeader().SequenceNumber} : RandomNumber;
            } else { //macsec
                Aso.crypto_sequence_number = PsaPacket.PsaControlDesc.packet_source not in [sx] ? %{PsaPacket.PsaControlDesc.crypto_sequence_number_high, GetMACSecHeader(Packet).PacketNumber} : RandomNumber;
            };
            Aso.high_bound_msb_new  = PsaPacket.PsaControlDesc.high_bound_msb_new;
            if PsaPacket.PsaControlDesc.packet_source in [sx] {
                Aso.PatchField(crypto_sequence_number);
            };
        };
        if ((Aso.aso_context_type) == policer) {
            Aso.ip_header_and_payload_length = GetIpHeaderAndPayloadLength(PsaPacket);
            //var SizeToRemoveFromPacketLength: uint = (PsaPacket.Decapsulated or PsaPacket.Encapsulated) and PsaPacket.PsaControlDesc.packet_source != sx and PsaPacket.FcsRemoved ? FCS_LEN : 0;
            Aso.packet_length                = UNITS(Psa,InstanceIndex).SteeringWbVerifier.GetPacketLength(EnvSlice, PsaPacket); 
        };
        if ((Aso.aso_context_type) == connection_tracking) {
            if (Packet.GetFirstPacketWithTCPHeader() == NULL) {
                DUTError(201,"ASO action is connection_tracking but no TCP headers in this packet");
            };
            var PacketInput          : PackInput    = new;
            var TCPHeaderListOfBytes : list of byte = EthPacket.GetFirstPacketWithTCPHeader().TCPHeader().Pack(PacketInput);
            Aso.tcp_header             = ListOfBytesToBus(TCPHeaderListOfBytes[0..19],20);
            Aso.tcp_payload_length     = Packet.GetFirstPacketWithTCPHeader().TCPHeader().TcpPayload.size();// should decrease TCP header (= data_offset (4b in DWORD) x4 )
            Aso.tcp_ack_biggest_sn     = Packet.GetFirstPacketWithTCPHeader().TCPHeader().AckSeqNum;
            Aso.connection_tracking_ok = PsaPacket.PffChecks.connection_tracking_ok;
        };
        messagef(HIGH,"Psa2Aso I/F"){
            Aso.PrintTrc("Aso:","");
        };
    };

    GetIpHeaderAndPayloadLength(PsaPacket : ParserEntryPacket) : uint(bits : PSA2ASO_DESC_IP_HEADER_AND_PAYLOAD_LENGTH_WIDTH) is {
        var EnvSlice  : SteeringSlice = UNITS(Psa, InstanceIndex).SteeringWbVerifier.EnvSlices[PsaPacket.SliceId];
        var EthPacket                       : NetworkPacket = GetEthPacket(PsaPacket.PsaNetworkPacket);
        var count_packet_length_in_policers : bit           = GetCountPacketLength();
        if count_packet_length_in_policers == 1'b1 {
            return UNITS(Psa,InstanceIndex).SteeringWbVerifier.GetPacketLength(EnvSlice, PsaPacket);  
        };
        if EthPacket.HasHeader(IPv6) {return EthPacket.IPv6Header().PayloadLen + EthPacket.IPv6Header().GetHeaderSizeForModifiedHeadersSize()};
        if EthPacket.HasHeader(IPv4) {return EthPacket.IPv4Header().TotalLength};
    };

    GetCountPacketLength() : bit is {
        return CrPsaPrefix.CRREG(CR_STEERING_COMMIT.count_packet_length_in_policers).data;
    };

    UpdateSxTransmit(Action : SteeringAction) is {
        var SingleAction : steering_entry_action_single_desc = Action.steering_entry_action_single_desc;
        SxTransmit.Valid              = TRUE;
        SxTransmit.Sniffer            = SingleAction.sx_sniffer_enable.as_a(bool) ? SingleAction.sx_sniffer.as_a(bool) : SxTransmit.Sniffer;
        SxTransmit.Wire               = SingleAction.sx_wire_enable.as_a(bool) ? SingleAction.sx_wire.as_a(bool)       : SxTransmit.Wire;
        SxTransmit.TransmitNow        = SingleAction.sx_transmit_now.as_a(bool);
        SxTransmit.FunctionalLoopback = SingleAction.sx_func_lb_enable.as_a(bool) ? SingleAction.sx_func_lb.as_a(bool) : SxTransmit.FunctionalLoopback;
        SxTransmit.LoopbackSyndrome   = (SxTransmit.LoopbackSyndrome & (~SingleAction.loopback_syndrome_en)) | (SingleAction.loopback_syndrome_en & SingleAction.loopback_syndrome);
        SxTransmit.CollectCoverage();
        messagef(MEDIUM,"SxTransmit action:\t"){
            SxTransmit.PrintMe();
        };
    };
    UpdateInlineQp(Action : SteeringAction,EntryGvmi : uint(bits : 16)) is {
        var SingleAction : steering_entry_action_single_desc = Action.steering_entry_action_single_desc;
        InlineQp          = new;
        InlineQp.Valid    = TRUE;
        InlineQp.QPNumber = SingleAction.inline_qpn;
        InlineQp.Gvmi     = EntryGvmi;
        InlineQp.CollectCoverage();
        messagef(MEDIUM,"InlineQp action:\t"){
            InlineQp.PrintMe();
        };
    };
    UpdateQpList(Action : SteeringAction, QpListPointerGvmi : uint(bits : 16), QpListGvmi : uint(bits:16)) is {
        var SingleAction : steering_entry_action_single_desc = Action.steering_entry_action_single_desc;
        QpList               = new;
        QpList.Valid         = TRUE;
        QpList.QpListPointer = SingleAction.qp_list_pointer;
        QpList.QpListGvmi    = QpListGvmi;
        for CacheLineRequestNumber from 0 to 20{ // arbitrary value.
            GetQpListFromMem(CacheLineRequestNumber, QpListPointerGvmi);
            if QpList.QpNumberList.has(it.Last == TRUE){ break};
        };
        QpList.NumOfQp = QpList.QpNumberList.size();
        QpList.CollectCoverage();
        messagef(MEDIUM,"QpListAction :\t"){
            outf("QpListPointer : %s\t",QpList.QpListPointer);
            outf("QpListGvmi    : %s\t",QpList.QpListGvmi);
            outf("QpNumberList  : \t");
            for each in QpList.QpNumberList{
                outf("%d - ",index);
                it.PrintMe();
            };
        };
    };

    UpdateQueueId(Action : SteeringAction) is {
        QueueId               = new;
        QueueId.FlowQ         = Action.steering_entry_action_single_desc.flow_q;
        QueueId.Profile       = Action.steering_entry_action_single_desc.profile;
        QueueId.RxTq          = Action.steering_entry_action_single_desc.rx_tq;
        QueueId.FlowQFromPrio = Action.steering_entry_action_single_desc.flow_q_from_prio;
        messagef(MEDIUM,"QueueId action:\t"){
            QueueId.PrintMe();
        };
        QueueId.CollectCoverage();
    };
    UpdateIterator(Packet : ParserEntryPacket,Action : SteeringAction,EntryGvmi : uint(bits : 16),SE : SteeringEntry) is {
        Packet.IteratorOccured=TRUE;
        if Packet.IterationLevel >= 3{
            DUTError(100,"Iterator depth more than 3, FcId=%d, SliceId=%d, PktId=%s",Packet.FcId,Packet.PsaControlDesc.slice_id,Packet.PsaControlDesc.packet_id);
            return;
        };
//        var SteeringContext : SteeringActions = deep_copy(me);
        if Iterator == NULL{
            Iterator = new;
        };
        Iterator.Valid = TRUE;
        CheckAndBuildIteratorWithNext(Packet,SE);
        BuildIteratorList(Packet,Action,EntryGvmi,SE);
        messagef(MEDIUM,"Iterator action:\t "){
            Iterator.PrintMe();
        };
        IteratorActionHasOccured=TRUE;
    };

    CheckAndBuildIteratorWithNext(Packet : ParserEntryPacket,SE : SteeringEntry) is {
        if not (SE.steering_entry_next_desc.next_table_base_39_32 == 0x0 and SE.steering_entry_next_desc.next_table_base_31_5_size == 0x0){
            CollectCoverageSteeringEntryIterator(SE);
            var IteratorIndicator : IteratorIndicator = new;
            IteratorIndicator.Original      = TRUE;--Need to calc correct VA after hash params. save special value to be corrected in CacheRequest.
            IteratorIndicator.IteratorLevel = Packet.IterationLevel;
            messagef(HIGH,"Adding Iterator packet: VA=%s,Level=%d",IteratorIndicator.VA,IteratorIndicator.IteratorLevel);
            Iterator.IteratorList.add0(IteratorIndicator);
        };
    };

    BuildIteratorList(Packet : ParserEntryPacket,Action : SteeringAction,EntryGvmi : uint(bits : 16),SE : SteeringEntry) is {
        var IterationPointer : uint(bits : STEERING_ENTRY_ACTION_DOUBLE_DESC_ITERATIONS_TABLE_POINTER_WIDTH) = Action.steering_entry_action_double_desc.iterations_table_pointer;
        var NumOfIterations  : uint(bits : STEERING_ENTRY_ACTION_DOUBLE_DESC_NUM_OF_ITERATIONS_WIDTH)        = Action.steering_entry_action_double_desc.num_of_iterations;
            var IteratorContext : IteratorContext = new;
            IteratorContext.Gvmi               = EntryGvmi;
            IteratorContext.Pkt                = deep_copy(Packet);
            IteratorContext.Pkt.IterationLevel = Packet.IterationLevel + 1;
            CollectIteratorVarsEvent(IteratorContext.Pkt.IterationLevel,NumOfIterations);
            IteratorContext.SteeringContext = deep_copy(me);
        messagef(HIGH,"Accumulated hash register = %s",IteratorContext.SteeringContext.AccumulatedHashRegister);
        Iterator.IteratorLevelCopy[IteratorContext.Pkt.IterationLevel] = IteratorContext;
        for Counter from NumOfIterations-1 down to 0{
            var IteratorIndicator : IteratorIndicator = new;
            IteratorIndicator.IteratorLevel = Packet.IterationLevel + 1;
            IteratorIndicator.VA            = HANDLERS(Mem).Icm.IndexToIcmVa(EntryGvmi,SteeringControl,IterationPointer + Counter);
            messagef(HIGH,"Adding Iterator packet: VA=%s,Level=%d",IteratorIndicator.VA,IteratorIndicator.IteratorLevel);
            Iterator.IteratorList.add0(IteratorIndicator);
        };
        Packet.IterationLevel += 1;
    };

    GetQpListFromMem(RequestNumber : uint, QpListPointerGvmi : uint(bits:16)) is {
        var QpIndex    : uint(bits : 64) = HANDLERS(Mem).Icm.IndexToIcmVa(QpListPointerGvmi, SteeringQpList, QpList.QpListPointer + RequestNumber);
        messagef(MEDIUM,"GetQpListFromMem | IcmIndex=0x%x | RequestNumber=0x%x | VA=0x%x", QpList.QpListPointer, RequestNumber, QpIndex);
        var QpListData : list of byte    = HANDLERS(Mem).Icm.ReadIcmVa(QpListPointerGvmi,SteeringQpList,QpIndex,64);
        QpList.QpNumberList.add(UnpackQpListCacheLine(ListOfBytesToBus(QpListData, 64)));
    };

    UnpackQpListCacheLine(Data : uint(bits : 512)) : list of QpListLine is {
        var DataInLines : list of uint = BusToListOfUint(Data, 16);
        for each (Line) in DataInLines{
            var QpNumberLine : QpListLine = new;
            QpNumberLine.ForceResponder = Line[31:31].as_a(bool);
            QpNumberLine.Last           = Line[30:30].as_a(bool);
            QpNumberLine.QpNumber       = Line[23:0];
            result.add(QpNumberLine);
            if QpNumberLine.Last {return result};
        };
    };

    UpdateTir(Action : SteeringAction,EntryGvmi : uint(bits : 16)) is {
        var DoubleAction : steering_entry_action_double_desc = Action.steering_entry_action_double_desc;
        Action.steering_entry_action_single_desc = new;
        var SingleAction : steering_entry_action_single_desc = Action.steering_entry_action_single_desc;
        if DoubleAction.qp_list == 1{
            SingleAction.qp_list_pointer = DoubleAction.inline_qpn_qp_list;
            var QpListPointerGvmi : uint(bits:16) = HANDLERS(Steering).TirAsQpListUseQpGvmi ? Action.steering_entry_action_double_desc.gvmi : EntryGvmi;
            UpdateQpList(Action, QpListPointerGvmi, Action.steering_entry_action_double_desc.gvmi);
        } else {
            SingleAction.inline_qpn = DoubleAction.inline_qpn_qp_list;
            UpdateInlineQp(Action,Action.steering_entry_action_double_desc.gvmi);
        };
        TirActions                     = new;
        TirActions.ClassifiedAsTunnel  = DoubleAction.classified_as_tunneled;
        TirActions.TimeStampFromOrigin = DoubleAction.timestamp_from_port;
        TirActions.TimeStampFromPort   = DoubleAction.utc;
        messagef(MEDIUM,"TirActions:\t"){
            TirActions.PrintMe()
        };
    };

    UpdateFlowTag(Action : SteeringAction) is {
        FlowTag    = Action.steering_entry_action_single_desc.flow_tag;
        FlowTagVld = TRUE;
    };

    UpdateTlsIndex(Action : SteeringAction) is {
        TlsIndex    = Action.steering_entry_action_single_desc.tls_index;
        TlsIndexVld = TRUE;
    };


    UpdatePortSelection(Action : SteeringAction, ExpectedPkt : ParserEntryPacket) is {
        if Action.steering_entry_action_single_desc.port_number_enable == 1{
            PortNumber             = Action.steering_entry_action_single_desc.port_number;
            ExpectedPkt.PortNumber = Action.steering_entry_action_single_desc.port_number;
        };
    };

};

extend QueueIdActions{
    PrintMe() is {
        outf("RxTq : %s,\t",RxTq);
        outf("FlowQ : %s,\t",FlowQ);
        outf("Profile : %s,\t",Profile);
        outf("FlowQFromPrio : %s,\t",FlowQFromPrio);
    };
};

extend SxTransmitActions{
    PrintMe() is{
        outf("Sniffer : %s\t,",Sniffer);
        outf("FunctionalLoopback : %s\t,",FunctionalLoopback);
        outf("Wire : %s\t,",Wire);
        outf("LoopbackSyndrome : %s\t,",LoopbackSyndrome);
        outf("TransmitNow : %s",TransmitNow);
    };
};

extend InlineQpActions{
    PrintMe() is{
        outf("QpNumber: %s\t",QPNumber);
        outf("Gvmi: %s",Gvmi);
    };
};

extend QpListLine {
    PrintMe() is{
        outf("ForceResponder : %s\t,",ForceResponder);
        outf("Last : %s\t,",Last);
        outf("QpNumber : %s\t",QpNumber);
    };
};

extend RssActions{
    PrintMe() is{
        outf("QpNumber: %s    ",QpNumber);
        outf("Gvmi: %s    ",Gvmi);
        outf("RssHashResult: %s    ",RssHashResult);
        outf("RssHashType: %s    ",RssHashType);
    };
};

extend TirActions{
    PrintMe() is{
        outf("TimeStampFromOrigin: %s\t",TimeStampFromOrigin);
        outf("TimeStampFromPort: %s\t",TimeStampFromPort);
        outf("ClassifiedAsTunnel: %s\t",ClassifiedAsTunnel);
    };
};

extend IteratorActions{
    GetNextIteratorContext(IteratorIndicator : IteratorIndicator) : IteratorContext is also {
        var Level : uint = IteratorIndicator.IteratorLevel;
        if IteratorIndicator.Original{
            Level += 1;
        };
        for L from Level+1 to 3 {
            IteratorLevelCopy[L] = NULL;
        };
        result = deep_copy(IteratorLevelCopy[Level]);
        if IteratorIndicator.Original{ 
            result.Pkt.IterationLevel -= 1;
            
        };
    };

    PrintMe() is {
        outf("IteratorList size: %d    ",IteratorList.size());
        outf("IteratorLevel: %d",IteratorList.first(TRUE).IteratorLevel);
    };
};

extend CryptoActions {
    PrintMe() is {
        outf("IPSecAction:\n");
        outf("===========\n");
        outf("Valid: %s\n", Valid);
        outf("SaDbContextIndex: 0x%x\n", SaDbContextIndex);
        outf("Gvmi: 0x%x\n", Gvmi);
    };
};
'>
