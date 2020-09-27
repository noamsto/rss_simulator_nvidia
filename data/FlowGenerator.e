// MTL-HEADER //////////////////////////////////////////////////////////////////////
// This Program is the Confidential and Proprietary product of
// Mellanox Technologies LTD. Any unauthorized use, reproduction
// or transfer of this program is strictly prohibited.
// Copyright (c) 1999 by Mellanox Technologies LTD All Rights Reserved.
// EOH /////////////////////////////////////////////////////////////////////////////

<'

import FlowGenerator_ih;
import SteeringFlowCoverage;
import FlowGeneratorAction;

extend RssDataBase {
	RssOnInnerParams(SteeringBranch : list of SteeringNode) : bool is also {
		var SteeringNode : SteeringNode = SteeringBranch.first(it.LevelInTree == SteeringBranch.max_value(it.LevelInTree));
		if RssSubType == ToplitzInner {
			return TRUE;
		} else if RssSubType == ToplitzByDecap and SteeringNode.SteeringNodeInDecapsulationEnabledFlow(TRUE) {
			return TRUE;
		};
		return FALSE;
	};
};

extend FlowGenerator{
	StaticConfig() is also{
		InitNumOfFlows();
		GenerateFlows();
		FillPffOKs();
		PrintTrees();
		PrintSteeringActions();
		PrintEncapsulationPackets();
	};

	MulticastStaticConfig() is also {
		GenerateMulticastFlows();
		FillPffOKs(TRUE);
		PrintTrees(TRUE);
		PrintSteeringActions(TRUE);
		PrintEncapsulationPackets(TRUE);
	};

	InitNumOfFlows() is {
		gen MultiFlowsToOneQp;
		gen GeneratedNumOfFlowsPerQp;
		NumOfFlowsPerQp = GeneratedNumOfFlowsPerQp;
		messagef(MEDIUM,"NumOfFlowsPerQp = 0x%x",NumOfFlowsPerQp);
		gen MaxNumOfFlowsInPort;
		gen IBPortSteeringMode;
		messagef(MEDIUM,"IBPortSteeringMode = %s",IBPortSteeringMode);
		for each (PortNum) in  TOPOLOGY.GetClusterActiveLogicalPorts(External).all(it.LinkProtocol == IB).LogicalPortNum {
			MaxHairPinModeIB+= MaxNumOfFlowsInPort[PortNum];
		};
		for each (PortNum) in  TOPOLOGY.GetClusterActiveLogicalPorts(External).all(it.LinkProtocol == MAC).LogicalPortNum {
			MaxHairPinModeMAC+= MaxNumOfFlowsInPort[PortNum];
		};
		messagef(MEDIUM,"MaxHairPinModeIB 0x%x MaxHairPinModeMAC 0x%x", MaxHairPinModeIB, MaxHairPinModeMAC);
		for each (MaxNumOfFlowsInPortNumber) in MaxNumOfFlowsInPort {
			var PortNumber : uint = index;
			messagef(MEDIUM,"Port: 0x%s - MaxNumOfFlowsInPort = %s, Number of ActiveGvmis on this Port %s",index, MaxNumOfFlowsInPortNumber, HANDLERS(Config).GetActiveGvmis().count(it.GvmiContexts.key_exists(PortNumber)));
			if MaxNumOfFlowsInPortNumber < HANDLERS(Config).GetActiveGvmis().count(it.GvmiContexts.key_exists(PortNumber)) {
				DUTError(911223,appendf("Port: 0x%x - MaxNumOfFlowsInPort=%s is less than Number of ActiveGvmis on this Port %s",index,MaxNumOfFlowsInPortNumber, HANDLERS(Config).GetActiveGvmis().count(it.GvmiContexts.key_exists(PortNumber))));
			};
		};
		for each (Port) in TOPOLOGY.GetClusterActiveLogicalPorts(External).LogicalPortNum {
			messagef(MEDIUM,"Generating MaxFlowsPerGvmi for Port: 0x%x", Port);
			var GvmiList : list of GvmiInfo;
			GvmiList = HANDLERS(Config).GetActiveGvmis().all(it.GvmiContexts.key_exists(Port));
			NumOfEthGvmi = HANDLERS(Config).GetActiveGvmis().count(it.GvmiContexts.key_exists(Port));
			var MaxNumOfFlowsInCurPort : uint =  MaxNumOfFlowsInPort[Port];
			MaxFlowsPerPort[Port] = new;
			if NumOfEthGvmi != 0 and MaxNumOfFlowsInCurPort != 0{
				MaxFlowsPerPort[Port].MaxFlowsPerGvmi = GenDistribution(MaxNumOfFlowsInCurPort,NumOfEthGvmi, 1 ,MaxNumOfFlowsInCurPort,0,UniformDistribution);
				for each in MaxFlowsPerPort[Port].MaxFlowsPerGvmi {
					if MultiFlowsToOneQp {
						MaxFlowsPerPort[Port].MaxFlowsPerGvmi[index] = MaxFlowsPerPort[Port].MaxFlowsPerGvmi[index];
					} else {
						MaxFlowsPerPort[Port].MaxFlowsPerGvmi[index] = MaxFlowsPerPort[Port].MaxFlowsPerGvmi[index];
					};
				};
			};
		};
	};


	GenerateFlows() is {
		for each (Port) in TOPOLOGY.GetClusterActiveLogicalPorts(External).LogicalPortNum{
			GvmiIndex = 0;
			for each (GvmiInfo) in HANDLERS(Config).GetActiveGvmis().all(it.GvmiContexts.key_exists(Port)) {
				if !MaxFlowsPerPort[Port].MaxFlowsPerGvmi.is_empty() and MaxFlowsPerPort[Port].MaxFlowsPerGvmi[GvmiIndex] > 0 {
					var UnicastSteeringTree : SteeringTree = new;
					UnicastFlowsList.add(UnicastSteeringTree);
					InitTree(FALSE,UnicastSteeringTree,GvmiInfo,Port,MaxFlowsPerPort[Port].MaxFlowsPerGvmi[GvmiIndex]);
					for each (Child) in UnicastSteeringTree.RootNode.Children{
						if Child.MaxNumOfChildren != 0 {
							Child.BuildTree(UnicastSteeringTree,UnicastSteeringTree.MaxNumOfFlowsCounter,GvmiInfo,Child.MustReWriteInNextChild());
						};
					};
					WriteGidTable(UnicastSteeringTree);
					MarkFullIndication(UnicastSteeringTree);
				};
				GvmiIndex += 1;
			};
		};
	};

	GenerateMulticastFlows() is {
		for each (Port) in TOPOLOGY.GetClusterActiveLogicalPorts(External).LogicalPortNum {
			if TOPOLOGY.GetClusterActiveLogicalPort(Port,External).LinkProtocol == MAC {
				for each (GvmiInfo) in HANDLERS(Config).GetActiveGvmis().all(it.GvmiContexts.key_exists(Port)) {
					if HANDLERS(Steering).MulticastGroupHandler.MulticastGroupList.has(it.Port == Port and it.Gvmi == GvmiInfo.GvmiContexts.key(Port).GvmiNum and it.NumberOfLocalQps > 0) {
						var MulticastSteeringTree : SteeringTree = new;
						MulticastFlowsList.add(MulticastSteeringTree);
						InitTree(TRUE,MulticastSteeringTree,GvmiInfo,Port,UNDEF);
						for each (Child) in MulticastSteeringTree.RootNode.Children {
							if Child.MaxNumOfChildren != 0 {
								Child.BuildTree(MulticastSteeringTree,MulticastSteeringTree.MaxNumOfFlowsCounter,GvmiInfo);
							};
						};
					};
				};
			};
		};
	};

	MarkFullIndication(SteeringTree : SteeringTree) is {
		for each (Node) in SteeringTree.GetAllChildren(){
			if (Node.Children.has(it.ValueType == AllValues)){
				Node.IsFull = TRUE;
			};
		};
	};

	WriteGidTable(Tree : SteeringTree) is {
		var ListOfUsedIndices : list of uint;
		var FreeIndices : list of uint = HANDLERS(Config).GetActiveGvmis().key(Tree.Gvmi).GvmiContexts.key(Tree.Port).GidTable.Index;
		if (HANDLERS(Config).GetPortConfigInfo(Tree.Port).PortInfo.LinkProtocol != IB) {
			FreeIndices.resize(HANDLERS(Config).MaxGidsInPort);
			for i from 1 to HANDLERS(Config).MaxGidsInPort {
				FreeIndices[i-1] = i-1;
			};
		};
		for each (Node) in Tree.RootNode.Children{
			if ((Node.Kind in [Mac,MacByDecap] and Node.IsRoce and Node.Children.is_empty()) or Node.GetAllChildren().has(it.IsRoce and it.Children.is_empty())) and !FreeIndices.is_empty() {
				WriteToTable(FreeIndices,ListOfUsedIndices,Tree.Gvmi,Tree.Port,Node,TRUE);
			};
		};
		for each (Node) in Tree.RootNode.Children {
			if (Node.Kind in [Mac,MacByDecap] and !Node.IsRoce and !FreeIndices.is_empty()) {
				WriteToTable(FreeIndices,ListOfUsedIndices,Tree.Gvmi,Tree.Port,Node,FALSE); // TODO ori, please check if it's ok to write this in ETHoIB
			};
		};
		messagef(MEDIUM, "GidTable for GvmiNum=%s, PortNum=%s\n", Tree.Gvmi, Tree.Port) {
			outf("GidTable: Index, Gid, MyMac (%s) \n", HANDLERS(Config).GetActiveGvmis().key(Tree.Gvmi).GvmiContexts.key(Tree.Port).AsAString());
			for each (GidInfo) in HANDLERS(Config).GetActiveGvmis().key(Tree.Gvmi).GvmiContexts.key(Tree.Port).GidTable {
				outf("%s\n", GidInfo.AsAString());
			};
		};
		HANDLERS(Config).WriteGidMacTable(HANDLERS(Config).GetActiveGvmis().key(Tree.Gvmi).GvmiContexts.key(Tree.Port));
	};

	WriteToTable(FreeIndices : list of uint, ListOfUsedIndices : list of uint,Gvmi : uint(bits:16),Port : uint,Node : SteeringNode,RoCE : bool) is{
		var NumOfIterations : uint = RoCE and Write2GidTableEntriesPerRoce ? 2 : 1;
		if sys.GlobalVariables.PerformanceTest != None and not sys.GlobalVariables.PerfTestParameters.PerformanceStubEnable {
			NumOfIterations = 1;
		};
		var RRoceTypeForFirstIteration : RoCEType;
		for i from 0 to NumOfIterations-1{
			var Index : uint;
			gen Index keeping{
				it in FreeIndices;
			};
			if i == 0{
				gen SxInsertVlan keeping {
					read_only(Node.Children.max_value(it.VlanList.size()) >= HANDLERS(Config).GetPortConfigInfo(Port).PrioInfo.IpMaxOffsetFromMac) => it == FALSE;
				};
			};
			messagef(HIGH,"Updating Mac table with Mac %s Gvmi %s Port %s Index %s i = %s",Node.FieldValue,Gvmi,Port,Index,i);
			var GidInfo: GidInfo = HANDLERS(Config).GetActiveGvmis().key(Gvmi).GvmiContexts.key(Port).GidTable.key(Index);
			if (GidInfo == NULL) {
				gen GidInfo keeping {
					it.Index == Index;
					soft it.RoCEType == select { // Main type is RoCEv2 (Over UDP) others added for Legacy only
						45 : RRoCEUdpoIPv6;
						45 : RRoCEUdpoIPv4;
						4  : RRoCEoIPv6;
						4  : RRoCEoIPv4;
						2  : RoCEoGrh;
					};
					read_only(Node.IsRoce and Node.GetAllChildren().has(it.Kind in [Ipv6Dst,Ipv6Src,Ipv6L4])) => it.RoCEType == RRoCEUdpoIPv6;
					read_only(Node.IsRoce and Node.GetAllChildren().has(it.Kind in [Ipv4Dst,Ipv4Src,Ipv4_5Tuple,L4Only])) => it.RoCEType == RRoCEUdpoIPv4;
					read_only(HANDLERS(Config).GetActiveGvmis().key(Gvmi).GvmiContexts.key(Port).RxStripCvlan) => it.RxAllowNoVlan == TRUE;
					read_only(it.RoCEType == RoCEoGrh) => it.Gid[127:120] != 0xff;
					read_only(Node.Kind == MacByDecap and HANDLERS(Config).GetLogicalPortConfigInfoList().key(Port).PrioInfo.RxPrioSourceType in [MplsExpDscpDefault, DscpDefault]) => it.RoCEType not in [RoCEoGrh];
				};
				HANDLERS(Config).GetActiveGvmis().key(Gvmi).GvmiContexts.key(Port).GidTable.add(GidInfo);
			};
			if i == 0 {
				RRoceTypeForFirstIteration = GidInfo.RoCEType;
			};
			if i == 1 {
				GidInfo.RoCEType = RRoceTypeForFirstIteration;
			};
			GidInfo.MyMac =  Node.FieldValue;
			if GidInfo.RoCEType == RRoCEUdpoIPv6 and Node.GetAllChildren().has(it.Kind in [Ipv6Dst]) {
				GidInfo.Gid = Node.GetAllChildren().first(it.Kind in [Ipv6Dst]).FieldValue;
			} else if Node.GetAllChildren().has(it.Kind in [Ipv4Dst]) {
				GidInfo.Gid[31:0] = Node.GetAllChildren().first(it.Kind in [Ipv4Dst]).FieldValue[31:0];
			};
			GidInfo.SxInsertVlan =  i == 0 ? SxInsertVlan : !SxInsertVlan;
			GidInfo.VlanId = GetRanomVlan();
			var IndexToBeRemoved : uint = FreeIndices.first_index(it == Index);
			FreeIndices.fast_delete(IndexToBeRemoved);
			ListOfUsedIndices.add(Index);
		};
	};

	GetRanomVlan() : uint(bits:12) is {
		var ListOfVlanNodes : list of SteeringNode = GetAllNodesWithSpecificType(Vlan);
		if !ListOfVlanNodes.is_empty(){
			var Index : uint;
			gen Index keeping{
				it < ListOfVlanNodes.size();
			};
			return ListOfVlanNodes[Index].VlanList[0].VlanID;
		};
	};

	InitTree(MulticastFlow : bool, Tree : SteeringTree, GvmiInfo : GvmiInfo, TreePort : uint ,NumOfTreeFlows : uint) is {
		var TreeGvmi : uint(bits:16) = GvmiInfo.GvmiNum;
		Tree.Gvmi = TreeGvmi;
		Tree.Port = TreePort;
		Tree.GvmiResolutionMode = GvmiResolutionMode;
		if not MulticastFlow {
			Tree.MaxNumOfFlowsInTree = NumOfTreeFlows;
		};
		Tree.RootNode = new;
		Tree.RootNode.SteeringTree = Tree;
		Tree.RootNode.LevelInTree = 0;
		Tree.RootNode.NodeIndex = NodeIndex;
		CurSteeringTree = Tree;
		Tree.MulticastTree = MulticastFlow;
		Tree.ConfigAllowedPrio();
		Tree.ListOfNodes.add(Tree.RootNode);
		NodeIndex += 1;
		var MulticastGroupListPerPortGvmi : list of MulticastGroup = {};
		if MulticastFlow {
			MulticastGroupListPerPortGvmi = HANDLERS(Steering).MulticastGroupHandler.MulticastGroupList.all(it.Port == TreePort and it.Gvmi == TreeGvmi);
		};
		gen Tree.NumOfRootChildren keeping {
			read_only(MulticastFlow) => it == MulticastGroupListPerPortGvmi.size();
		};
		gen Tree.IBSteeringMode keeping {
			read_only(TOPOLOGY.GetClusterActiveLogicalPort(TreePort,External).LinkProtocol == IB and IBPortSteeringMode == IbOnly) => it == IbOnly;
			read_only(TOPOLOGY.GetClusterActiveLogicalPort(TreePort,External).LinkProtocol == IB and IBPortSteeringMode == IpoIbAndIb) => soft it == select {
				50 : IbOnly;
				50 : IpoIbOnly;
			};
			read_only(Tree.MaxNumOfFlowsInTree == Tree.NumOfRootChildren) => it != IpoIbOnly;
		};
		if Tree.IBSteeringMode == IpoIbOnly {
			gen Tree.IpoIBType keeping {
				soft it == select {
					50 : [IPv4Dst,IPv4Src,IPv45Tuple];
					50 : IPv6Dst;
					10 : IPv6Src;
				};
			};
		};
		Tree.RootNode.IBSteeringMode = Tree.IBSteeringMode;
		Tree.RootNode.IpoIBType = Tree.IpoIBType;
		if TOPOLOGY.GetClusterActiveLogicalPort(Tree.Port,External).LinkProtocol == MAC {
			NumOfMacPerPort[Tree.Port] += Tree.NumOfRootChildren;
		};
		if Tree.NumOfRootChildren != 0 {//we put 1 in min num of children since 0 children counts for 1 child
			var MaxNumOfChildrenList : list of uint;
			if MulticastFlow {
				MaxNumOfChildrenList = GetMaxNumOfChildrenListFromMulticastGroupListPerPortGvmi(MulticastGroupListPerPortGvmi);
			} else {
				MaxNumOfChildrenList = GenDistribution(Tree.MaxNumOfFlowsInTree,Tree.NumOfRootChildren, 1 , Tree.MaxNumOfFlowsInTree ,0,FALSE);
			};
			for i from 0 to Tree.NumOfRootChildren-1 {
				gen NewRootChild keeping {
					it.MulticastNode == read_only(MulticastFlow);
					it.NodeIndex == read_only(NodeIndex);
					it.ValueType == CertainValue;
					it.LevelInTree == 1;
					it.SteeringTree == read_only(Tree);
					it.IBSteeringMode == read_only(Tree.RootNode.IBSteeringMode);
					it.IpoIBType == read_only(Tree.RootNode.IpoIBType);
					it.MaxNumOfChildren == read_only(MaxNumOfChildrenList[i]);
					it.Register0InUse == Tree.RootNode.Register0InUse;
					it.Register1InUse == Tree.RootNode.Register1InUse;
					it.Register2InUse == Tree.RootNode.Register2InUse;
					it.Register3InUse == Tree.RootNode.Register3InUse;
					it.Register4InUse == Tree.RootNode.Register4InUse;
					it.Register5InUse == Tree.RootNode.Register5InUse;
					it.RxRegister0Value == Tree.RootNode.RxRegister0Value;
					it.RxRegister1Value == Tree.RootNode.RxRegister1Value;
					it.RxRegister2Value == Tree.RootNode.RxRegister2Value;
					it.RxRegister3Value == Tree.RootNode.RxRegister3Value;
					it.RxRegister4Value == Tree.RootNode.RxRegister4Value;
					it.RxRegister5Value == Tree.RootNode.RxRegister5Value;
					it.SxRegister0Value == Tree.RootNode.SxRegister0Value;
					it.SxRegister1Value == Tree.RootNode.SxRegister1Value;
					it.SxRegister2Value == Tree.RootNode.SxRegister2Value;
					it.SxRegister3Value == Tree.RootNode.SxRegister3Value;
					it.SxRegister4Value == Tree.RootNode.SxRegister4Value;
					it.SxRegister5Value == Tree.RootNode.SxRegister5Value;
					read_only(TOPOLOGY.GetClusterActiveLogicalPort(Tree.Port,External).LinkProtocol == IB) => it.Kind == Lid;
					read_only(TOPOLOGY.GetClusterActiveLogicalPort(Tree.Port,External).LinkProtocol == MAC) => it.Kind == Mac;
				};
				if MulticastFlow {
					NewRootChild.MulticastGroup = MulticastGroupListPerPortGvmi[i];
				};
				if TOPOLOGY.GetClusterActiveLogicalPort(Tree.Port,External).LinkProtocol == IB and GvmiResolutionMode == GID {
					HandleLidRoot(NewRootChild,Tree.Port,HANDLERS(Config).GetLogicalPortConfigInfoList().key(TreePort).LidInfo.Lid,HANDLERS(Config).GetLogicalPortConfigInfoList().key(TreePort).LidInfo.Lmc);
				} else if TOPOLOGY.GetClusterActiveLogicalPort(Tree.Port,External).LinkProtocol == IB and GvmiResolutionMode == LID {
					HandleLidRoot(NewRootChild,Tree.Port,GvmiInfo.GvmiContexts.key(Tree.Port).LidInfo.Lid,GvmiInfo.GvmiContexts.key(Tree.Port).LidInfo.Lmc);
				} else { // MAC Port
					HandleMacRoot(NewRootChild);
				};
				Tree.RootNode.AddChild(1,NewRootChild);
				Tree.ListOfNodes.add(NewRootChild);
				NodeIndex += 1;
			};
			if Tree.RootNode.Children.size() == 0{
				DUTError(923,appendf("no children for root node of Gvmi %s",TreeGvmi));
			};
		};
		HANDLERS(LocalQp).FlowGenerator.PublishSteeringNode(Tree.RootNode);
		PublishSteeringTree(Tree);
	};

	GetMaxNumOfChildrenListFromMulticastGroupListPerPortGvmi(MulticastGroupListPerPortGvmi : list of MulticastGroup) : list of uint is {
		for i from 0 to MulticastGroupListPerPortGvmi.size()-1 {
			var MulticastGroupNumberOfLocalQps : uint = MulticastGroupListPerPortGvmi[i].NumberOfLocalQps;
			result.add(MulticastGroupNumberOfLocalQps);
		};
		return result;
	};

	HandleMacRoot(SteeringNode : SteeringNode) is {
		var Mac : uint(bits:48);
		if SteeringNode.MulticastNode {
			Mac = SteeringNode.MulticastGroup.Mac;
		} else {
			Mac = DMacGenerator.GenNum();
			var NumOfReWriteDmacGeneratorsTries : uint = 0x0;
			while IsReWrittenMac(Mac) {
				Mac = DMacGenerator.GenNum();
				if NumOfReWriteDmacGeneratorsTries > 0x1000 {
					DUTError(999222,appendf("HandleMacRoot - DMacGenerator.GenNum seems like stuck, please check SerialGeneration"));
				};
				NumOfReWriteDmacGeneratorsTries += 1;
			};
			if Mac[40:40] == 1{
				Mac[40:40] = 0;
				DMacGenerator.OldNums.add(Mac);
			}else{
				var TmpMac : uint(bits:48) = Mac;
				TmpMac[40:40] = 1;
				DMacGenerator.OldNums.add(TmpMac);//we want to prevent MC mac being generated so we add both options to old nums in mac
			};
		};
		SteeringNode.FieldValue = Mac;
		if SteeringNode.Kind == Mac {
			gen SteeringNode.HairPinMode keeping {
				read_only(not SteeringNode.SteeringTree.RootNode.Children.has(it.HairPinMode == None)) => it == None;
				it in [None, BridgeHairPin];
				read_only(SteeringNode.MulticastNode) => it == None;
			};
		};
		if SteeringNode.HairPinMode in [BridgeHairPin] {
			GlobalHairPinModeCounterMAC += 2;
		};
		if SteeringNode.HairPinMode not in [None] or SteeringNode.MulticastNode {
			SteeringNode.IsRoce = FALSE;
			SteeringNode.RoCE = FALSE;
		};
		if SteeringNode.Kind == Mac {
			gen SteeringNode.RemoteFlow keeping {
				read_only(SteeringNode.HairPinMode != None or SteeringNode.SteeringTree.RootNode.Children.size() == 0) => it == FALSE;
				read_only(not SteeringNode.SteeringTree.RootNode.Children.has(it.RemoteFlow == FALSE)) => it == FALSE;
				read_only(SteeringNode.MulticastNode) => it == FALSE;
			};
		};
		messagef(MEDIUM,"Root Mac %s is of HairPinMode %s and RemoteFlow %s",Mac, SteeringNode.HairPinMode, SteeringNode.RemoteFlow);
		SteeringNode.InitSteeringInlineActions();
        SteeringNode.GenerateMACSecOnMacRootNode();
        if SteeringNode.MulticastNode or SteeringNode.RxMACSecHostType != None {
			SteeringNode.GenerateRxSteeringInlineActions();
			SteeringNode.GenerateSxSteeringInlineActions();
		};
		gen SteeringNode.WithRxInlineAction;
		gen SteeringNode.WithRxModificationActions keeping {
			read_only(SteeringNode.MulticastNode) => it == FALSE;
		};
		gen SteeringNode.WithSxInlineAction;
		gen SteeringNode.WithSxModificationActions keeping {
			read_only(SteeringNode.MulticastNode) => it == FALSE;
		};
        if SteeringNode.WithRxModificationActions {
			SteeringNode.GenerateRxSteeringModificationActions();
			if not SteeringNode.RxSteeringModificationActions.has(it.RxModificationActionType != None) {
				SteeringNode.RxSteeringModificationActions.clear();
				SteeringNode.WithRxModificationActions = FALSE;
			};
		};
		if SteeringNode.WithSxModificationActions {
			SteeringNode.GenerateSxSteeringModificationActions();
			if not SteeringNode.SxSteeringModificationActions.has(it.SxModificationActionType != None) {
				SteeringNode.SxSteeringModificationActions.clear();
				SteeringNode.WithSxModificationActions = FALSE;
			};
		};
		if SteeringNode.HairPinMode not in [None] {
		};
        
        if not VoqActionInRootEntries and  SteeringNode.Kind == Mac and not SteeringNode.SteeringNodeHasVOQActions() {
			DUTError(999333,appendf("HandleMacRoot - Root Children without VOQ"));
		};
	};
    
	HandleLidRoot(SteeringNode : SteeringNode,Port : uint,Lid : uint(bits:16),Lmc : uint(bits:3)) is {
		var LidMask : uint = 0xffff << Lmc;
		Lid = Lid & LidMask;
		SteeringNode.Lmc = Lmc;
		SteeringNode.FieldValue[111:96] = Lid;
		SteeringNode.InitSteeringInlineActions();
		SteeringNode.GenerateRxSteeringInlineActions();
		SteeringNode.GenerateSxSteeringInlineActions();
		gen SteeringNode.WithRxInlineAction;
		gen SteeringNode.WithRxModificationActions;
		gen SteeringNode.WithSxInlineAction;
		gen SteeringNode.WithSxModificationActions;
		if SteeringNode.WithRxModificationActions {
			SteeringNode.GenerateRxSteeringModificationActions();
			if not SteeringNode.RxSteeringModificationActions.has(it.RxModificationActionType != None) {
				SteeringNode.RxSteeringModificationActions.clear();
				SteeringNode.WithRxModificationActions = FALSE;
			};
		};
		if SteeringNode.WithSxModificationActions {
			SteeringNode.GenerateSxSteeringModificationActions();
			if not SteeringNode.SxSteeringModificationActions.has(it.SxModificationActionType != None) {
				SteeringNode.SxSteeringModificationActions.clear();
				SteeringNode.WithSxModificationActions = FALSE;
			};
		};
		gen SteeringNode.HairPinMode keeping {
			read_only(not SteeringNode.SteeringTree.RootNode.Children.has(it.HairPinMode == None)) => it == None;
			it not in [EthHairPin];
		};
		if SteeringNode.HairPinMode in [IPoIBGW, BridgeHairPin] {
			messagef(MEDIUM,"HandleLidRoot: HairPinMode is BridgeHairPin/IPoIBGW, increasing GlobalHairPinModeCounterIB from 0x%x to 0x%x",
				GlobalHairPinModeCounterIB, GlobalHairPinModeCounterIB+1);
			GlobalHairPinModeCounterIB += 1;
			if SteeringNode.HairPinMode in [IPoIBGW] {
				messagef(MEDIUM,"HandleLidRoot: HairPinMode is IPoIBGW, increasing GlobalHairPinModeCounterMAC from 0x%x to 0x%x",
					GlobalHairPinModeCounterMAC, GlobalHairPinModeCounterMAC + (1 << Lmc));
				GlobalHairPinModeCounterMAC += (1 << Lmc);
			};
		};
		gen SteeringNode.RemoteFlow keeping {
			read_only(SteeringNode.HairPinMode != None or SteeringNode.SteeringTree.RootNode.Children.size() == 0) => it == FALSE;
			read_only(not SteeringNode.SteeringTree.RootNode.Children.has(it.RemoteFlow == FALSE)) => it == FALSE;
		};
		messagef(MEDIUM,"Root Lid %s is of HairPinMode %s RemoteFlow %s",Lid, SteeringNode.HairPinMode, SteeringNode.RemoteFlow);
		if not VoqActionInRootEntries and not SteeringNode.SteeringNodeHasVOQActions() and GvmiResolutionMode == GID { // in GvmiResolutionMode == LID VOQ will be added to Root Entry
			DUTError(999333,appendf("HandleLidRoot - Root Children without VOQ"));
		};
	};

	GetSteeringLookupTypeString(SteeringType,SteeringLookupType,BasicSteeringTypeStringLen : uint) : SteeringLookupType is {
		if SteeringType in [DUMMY_STEERING_TYPE] {
			var DummyExtensionString : string = str_sub(SteeringType.as_a(string), BasicSteeringTypeStringLen, 7);
			result = appendf("%s_%s",SteeringLookupType,DummyExtensionString).as_a(SteeringLookupType);
			return result;
		} else {
			return SteeringLookupType;
		};
	};

	FlowTypeToLookupType(SteeringType : SteeringType) : SteeringLookupType is{
		case SteeringType {
			[MAC_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,PortEthL2_1,3); };
			[VLAN_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,Vlan_1,4); };
			[WredMask] : { return WredMask; };
			[EndOfTree] : { return Nop; };
			[MPLS_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,MPLS_1,4); };
			[IPV6DST_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,EthL3Ipv6Dst_1,7); };
			[IPV6SRC_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,EthL3Ipv6Src_1,7); };
			[IPV45TUPLE_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,EthL3IPv45Tuple_1,11); };
			[IPV6L4_STEERING_TYPE_WITH_DUMMY,L4ONLY_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,EthL4_1,6); };
			[IPV4DST_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,EthL3Ipv4Dst_1,7); };
			[IPV4SRC_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,EthL3Ipv4Src_1,7); };
			[INNER_MAC_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,PortEthL2_2,8); };
			[INNER_VLAN_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,Vlan_2,9); };
			[INNER_MPLS_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,MPLS_2,9); };
			[INNER_IPV6DST_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,EthL3Ipv6Dst_2,12); };
			[INNER_IPV6SRC_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,EthL3Ipv6Src_2,12); };
			[INNER_IPV45TUPLE_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,EthL3IPv45Tuple_2,16); };
			[INNER_IPV6L4_STEERING_TYPE_WITH_DUMMY,INNER_L4ONLY_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,EthL4_2,11); };
			[INNER_IPV4DST_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,EthL3Ipv4Dst_2,12); };
			[INNER_IPV4SRC_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,EthL3Ipv4Src_2,12); };
			[TunnelType] : { return EthL2Tnl;};
			[MAC_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,PortEthL2_by_Decap,10); };
			[VLAN_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,Vlan_by_Decap,11); };
			[MPLS_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,MPLS_by_Decap,11); };
			[IPV6DST_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,EthL3Ipv6Dst_by_Decap,14);};
			[IPV6SRC_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,EthL3Ipv6Src_by_Decap,14);};
			[IPV45TUPLE_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,EthL3IPv45Tuple_by_Decap,18);};
			[IPV6L4_BY_DECAP_STEERING_TYPE_WITH_DUMMY,L4ONLY_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,EthL4_by_Decap,13);};
			[IPV4DST_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,EthL3Ipv4Dst_by_Decap,14); };
			[IPV4SRC_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,EthL3Ipv4Src_by_Decap,14); };
			[ESP_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,Esp_1,3); };
			[INNER_ESP_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,Esp_2,8); };
			[ESP_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : { return GetSteeringLookupTypeString(SteeringType,Esp_by_Decap,10); };
			[Register0] : { return SteeringRegisters_0; };
			[Register1] : { return SteeringRegisters_1; };
			[Register2] : { return SteeringRegisters_2; };
			[Register3] : { return SteeringRegisters_3; };
			[Register4] : { return SteeringRegisters_4; };
			[Register5] : { return SteeringRegisters_5; };
			[Lid] : { return PortIbL2; };
			[Gid] : { return IbL3; };
			default : { DUTError(2561,appendf("Unknown SteeringType %s",SteeringType));};
		};
	};

	GetNextLookupType(SteeringEntry : SteeringEntry) : SteeringLookupType is also{
		var BaseSteeringNode : SteeringNode = GetBaseSteeringNode(SteeringEntry);
		result = Nop;
		while !BaseSteeringNode.Children.has(it.ValueType == CertainValue){
			if BaseSteeringNode.Children.is_empty(){
				return Nop;
			}else{
				BaseSteeringNode = BaseSteeringNode.Children[0];
			};
		};
		if BaseSteeringNode.ValueType == CertainValue{
			result = FlowTypeToLookupType(BaseSteeringNode.Kind);
		};
	};

	GetRelevantPkt(SteeringNode : SteeringNode, Packet : NetworkPacket) : NetworkPacket is {
		if Packet.TunnelType in [IPoIB] {
			if SteeringNode.Kind in [   VLAN_STEERING_TYPE_WITH_DUMMY,
					MPLS_STEERING_TYPE_WITH_DUMMY,
					IPV6DST_STEERING_TYPE_WITH_DUMMY,
					IPV6SRC_STEERING_TYPE_WITH_DUMMY,
					IPV45TUPLE_STEERING_TYPE_WITH_DUMMY,
					IPV6L4_STEERING_TYPE_WITH_DUMMY,
					L4ONLY_STEERING_TYPE_WITH_DUMMY,
					IPV4DST_STEERING_TYPE_WITH_DUMMY,
					IPV4SRC_STEERING_TYPE_WITH_DUMMY,
					ESP_STEERING_TYPE_WITH_DUMMY,
					VLAN_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
					MPLS_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
					IPV6DST_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
					IPV6SRC_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
					IPV45TUPLE_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
					IPV6L4_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
					L4ONLY_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
					IPV4DST_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
					IPV4SRC_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
					ESP_BY_DECAP_STEERING_TYPE_WITH_DUMMY] {
				return Packet.InnerPacket;
			} else if Packet.InnerPacket != NULL and Packet.InnerPacket.TunnelType in [GRE,VXLAN,FlexParsing,GenericEncap] {
				if SteeringNode.Kind in [   IPV6DST_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
						IPV6SRC_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
						IPV45TUPLE_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
						IPV6L4_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
						L4ONLY_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
						IPV4DST_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
						IPV4SRC_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
						ESP_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
						INNER_MAC_STEERING_TYPE_WITH_DUMMY,
						INNER_VLAN_STEERING_TYPE_WITH_DUMMY,
						INNER_MPLS_STEERING_TYPE_WITH_DUMMY,
						INNER_IPV6DST_STEERING_TYPE_WITH_DUMMY,
						INNER_IPV6SRC_STEERING_TYPE_WITH_DUMMY,
						INNER_IPV45TUPLE_STEERING_TYPE_WITH_DUMMY,
						INNER_IPV6L4_STEERING_TYPE_WITH_DUMMY,
						INNER_L4ONLY_STEERING_TYPE_WITH_DUMMY,
						INNER_IPV4DST_STEERING_TYPE_WITH_DUMMY,
						INNER_IPV4SRC_STEERING_TYPE_WITH_DUMMY,
						INNER_ESP_STEERING_TYPE_WITH_DUMMY] {
					return Packet.InnerPacket.InnerPacket;
				} else if SteeringNode.Kind == TunnelType {
					return Packet.InnerPacket;
				};
			};
		} else if Packet.TunnelType == ESP and (SteeringNode.RxIPSecHostType != None or SteeringNode.SxIPSecHostType != None) and SteeringNode.Kind in [TunnelType,IPV6L4_STEERING_TYPE_WITH_DUMMY,L4ONLY_STEERING_TYPE_WITH_DUMMY] {
			return Packet.InnerPacket;
		} else if Packet.PktType in [RoCE,RRoCE_IP,RRoCE_UDP] {
			return Packet;
		} else if Packet.PktType in [Eth,IP] {
			if SteeringNode.Kind in [   MAC_STEERING_TYPE_WITH_DUMMY,
					VLAN_STEERING_TYPE_WITH_DUMMY,
					MPLS_STEERING_TYPE_WITH_DUMMY,
					IPV6DST_STEERING_TYPE_WITH_DUMMY,
					IPV6SRC_STEERING_TYPE_WITH_DUMMY,
					IPV45TUPLE_STEERING_TYPE_WITH_DUMMY,
					IPV6L4_STEERING_TYPE_WITH_DUMMY,
					L4ONLY_STEERING_TYPE_WITH_DUMMY,
					IPV4DST_STEERING_TYPE_WITH_DUMMY,
					IPV4SRC_STEERING_TYPE_WITH_DUMMY,
					ESP_STEERING_TYPE_WITH_DUMMY] {
				return Packet;
			} else if SteeringNode.Kind in [    MAC_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
					VLAN_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
					MPLS_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
					IPV6DST_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
					IPV6SRC_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
					IPV45TUPLE_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
					IPV6L4_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
					L4ONLY_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
					IPV4DST_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
					IPV4SRC_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
					ESP_BY_DECAP_STEERING_TYPE_WITH_DUMMY] {
				if SteeringNode.SteeringNodeInDecapsulationEnabledFlow(TRUE) and Packet.InnerPacket != NULL and Packet.TunnelType in [GRE,VXLAN,FlexParsing,GenericEncap,ESP] {
					return Packet.InnerPacket;
				} else {
					return Packet;
				};
			} else if Packet.InnerPacket != NULL and Packet.TunnelType in [GRE,VXLAN,FlexParsing,GenericEncap,ESP] {
				if SteeringNode.Kind in [   INNER_MAC_STEERING_TYPE_WITH_DUMMY,
						INNER_VLAN_STEERING_TYPE_WITH_DUMMY,
						INNER_MPLS_STEERING_TYPE_WITH_DUMMY,
						INNER_IPV6DST_STEERING_TYPE_WITH_DUMMY,
						INNER_IPV6SRC_STEERING_TYPE_WITH_DUMMY,
						INNER_IPV45TUPLE_STEERING_TYPE_WITH_DUMMY,
						INNER_IPV6L4_STEERING_TYPE_WITH_DUMMY,
						INNER_L4ONLY_STEERING_TYPE_WITH_DUMMY,
						INNER_IPV4DST_STEERING_TYPE_WITH_DUMMY,
						INNER_IPV4SRC_STEERING_TYPE_WITH_DUMMY,
						INNER_ESP_STEERING_TYPE_WITH_DUMMY] {
					return Packet.InnerPacket;
				} else if SteeringNode.Kind == TunnelType {
					return Packet;
				};
			};
		};
	};

	HeaderMatch(SteeringNode : SteeringNode,Packet : NetworkPacket, CheckOnlyIP : bool = FALSE) : bool is also{
		result = FALSE;
		var Pkt : NetworkPacket = GetRelevantPkt(SteeringNode,Packet);
		case SteeringNode.Kind{
			[MAC_STEERING_TYPE_WITH_DUMMY,INNER_MAC_STEERING_TYPE_WITH_DUMMY,MAC_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
				return (Pkt != NULL and Pkt.HasHeader(MAC) and Pkt.GetFirstHeader(MAC).as_a(MACHeaders).DestAddr == SteeringNode.FieldValue);
			};
			[MPLS_STEERING_TYPE_WITH_DUMMY,INNER_MPLS_STEERING_TYPE_WITH_DUMMY,MPLS_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
				return (Pkt != NULL and Pkt.HasHeader(MPLS) and MplsLabelsMatch(SteeringNode.MplsLabelHeader.MPLSLabelStackList,Pkt.GetFirstHeader(MPLS).as_a(MPLSHeader).MPLSLabelStackList,FALSE));
			};
			[VLAN_STEERING_TYPE_WITH_DUMMY,INNER_VLAN_STEERING_TYPE_WITH_DUMMY,VLAN_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
				return (Pkt != NULL and Pkt.HasHeader(MAC) and VlansMatch(SteeringNode.VlanList,Pkt.GetFirstHeader(MAC).as_a(MACHeaders).MacInternalHeaders,FALSE));
			};
			[IPV6DST_STEERING_TYPE_WITH_DUMMY,INNER_IPV6DST_STEERING_TYPE_WITH_DUMMY,IPV6DST_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
				return (Pkt != NULL and Pkt.HasHeader(IPv6) and Pkt.GetFirstHeader(IPv6).as_a(IPv6Header).DestGID == SteeringNode.FieldValue);
			};
			[IPV6SRC_STEERING_TYPE_WITH_DUMMY,INNER_IPV6SRC_STEERING_TYPE_WITH_DUMMY,IPV6SRC_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
				return (Pkt != NULL and Pkt.HasHeader(IPv6) and Pkt.GetFirstHeader(IPv6).as_a(IPv6Header).SrcGID == SteeringNode.FieldValue);
			};
			[IPV4DST_STEERING_TYPE_WITH_DUMMY,INNER_IPV4DST_STEERING_TYPE_WITH_DUMMY,IPV4DST_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
				return (Pkt != NULL and Pkt.HasHeader(IPv4) and Pkt.GetFirstHeader(IPv4).as_a(IPv4Header).DestAddress == SteeringNode.FieldValue);
			};
			[IPV4SRC_STEERING_TYPE_WITH_DUMMY,INNER_IPV4SRC_STEERING_TYPE_WITH_DUMMY,IPV4SRC_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
				return (Pkt != NULL and Pkt.HasHeader(IPv4) and Pkt.GetFirstHeader(IPv4).as_a(IPv4Header).SrcAddress == SteeringNode.FieldValue);
			};
			[IPV45TUPLE_STEERING_TYPE_WITH_DUMMY,INNER_IPV45TUPLE_STEERING_TYPE_WITH_DUMMY,IPV45TUPLE_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
				var DestAddressMatch : bool = (Pkt != NULL and Pkt.HasHeader(IPv4) and Pkt.GetFirstHeader(IPv4).as_a(IPv4Header).DestAddress == SteeringNode.FieldValue[127:96]);
				var SourceAddressMatch : bool = (Pkt != NULL and Pkt.HasHeader(IPv4) and Pkt.GetFirstHeader(IPv4).as_a(IPv4Header).SrcAddress == SteeringNode.FieldValue[95:64]);
				var SourcePortMatch : bool;
				var DestPortMatch : bool;
				if not CheckOnlyIP {
					SourcePortMatch = ((Pkt != NULL and Pkt.HasHeader(TCP) and Pkt.GetFirstHeader(TCP).as_a(TCPHeader).SrcPort == SteeringNode.FieldValue[63:48]) or
						(Pkt != NULL and Pkt.HasHeader(UDP) and Pkt.GetFirstHeader(UDP).as_a(UDPHeader).SrcPort == SteeringNode.FieldValue[63:48]));
					DestPortMatch = ((Pkt != NULL and Pkt.HasHeader(TCP) and Pkt.GetFirstHeader(TCP).as_a(TCPHeader).DestPort == SteeringNode.FieldValue[47:32]) or
						(Pkt != NULL and Pkt.HasHeader(UDP) and Pkt.GetFirstHeader(UDP).as_a(UDPHeader).DestPort == SteeringNode.FieldValue[47:32]));
				};
				return (DestAddressMatch and SourceAddressMatch and (CheckOnlyIP or SourcePortMatch and DestPortMatch));
			};
			[IPV6L4_STEERING_TYPE_WITH_DUMMY,L4ONLY_STEERING_TYPE_WITH_DUMMY,INNER_IPV6L4_STEERING_TYPE_WITH_DUMMY,INNER_L4ONLY_STEERING_TYPE_WITH_DUMMY,IPV6L4_BY_DECAP_STEERING_TYPE_WITH_DUMMY,L4ONLY_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
				var SourcePortMatch : bool = ((Pkt != NULL and Pkt.HasHeader(TCP) and Pkt.GetFirstHeader(TCP).as_a(TCPHeader).SrcPort == SteeringNode.FieldValue[79:64]) or
					(Pkt != NULL and Pkt.HasHeader(UDP) and Pkt.GetFirstHeader(UDP).as_a(UDPHeader).SrcPort == SteeringNode.FieldValue[79:64]));
				var DestPortMatch : bool = ((Pkt != NULL and Pkt.HasHeader(TCP) and Pkt.GetFirstHeader(TCP).as_a(TCPHeader).DestPort == SteeringNode.FieldValue[111:96]) or
					(Pkt != NULL and Pkt.HasHeader(UDP) and Pkt.GetFirstHeader(UDP).as_a(UDPHeader).DestPort == SteeringNode.FieldValue[111:96]));
				return (SourcePortMatch and DestPortMatch);
			};
			TunnelType : {
				if sys.GlobalVariables.ErrorTest {
					if Pkt == NULL {
						return FALSE;
					};
				};
				var TunnelIdMatch : bool = (Pkt != NULL and ((Pkt.HasHeader(VXLAN) and Pkt.GetFirstHeader(VXLAN).as_a(VXLANHeader).VNI == SteeringNode.FieldValue[63:40] and Pkt.GetFirstHeader(VXLAN).as_a(VXLANHeader).Reserved2 == SteeringNode.FieldValue[39:32]) or
						(Pkt.HasHeader(GRE) and Pkt.GetFirstHeader(GRE).as_a(GREHeader).GREType == NVGRE and Pkt.GetFirstHeader(GRE).as_a(GREHeader).VSID == SteeringNode.FieldValue[63:40] and Pkt.GetFirstHeader(GRE).as_a(GREHeader).FlowID == SteeringNode.FieldValue[39:32]) or
						(Pkt.HasHeader(GRE) and Pkt.GetFirstHeader(GRE).as_a(GREHeader).GREType != NVGRE and Pkt.GetFirstHeader(GRE).as_a(GREHeader).Key[31:0] == SteeringNode.FieldValue[63:32])));
				return TunnelIdMatch;
			};
			[ESP_STEERING_TYPE_WITH_DUMMY,INNER_ESP_STEERING_TYPE_WITH_DUMMY,ESP_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
				return (Pkt != NULL and Pkt.HasHeader(ESP) and Pkt.GetFirstHeader(ESP).as_a(ESPHeader).SPI == SteeringNode.FieldValue);
			};
			[STEERING_REGISTER_TYPES] : {
				return TRUE;
			};
			default : {
				DUTError(9364,appendf("unknown SteeringType (%s) in HeaderMatch",SteeringNode.Kind));
			};
		};
	};

	CorrectHeaderMissing(SteeringType : SteeringType,Pkt : NetworkPacket) : bool is also{
		case SteeringType{
			[Vlan,InnerVlan] : {
				return Pkt.GetFirstHeader(MAC).as_a(MACHeaders).MacInternalHeaders.is_empty();
			};
			[Ipv6Dst,InnerIpv6Dst,Ipv6DstByDecap] : {
				return !Pkt.HasHeader(IPv6);
			};
			default : {
				DUTError(9365,appendf("unknown SteeringType (%s) in CorrectHeaderMissing",SteeringType));
			};
		};
	};

	MplsLabelsMatch(FirstMplsLabels : list of MPLSLabelStack,SecondMplsLabels : list of MPLSLabelStack,CompareExactLabels : bool) :bool is also{
		result = TRUE;
		if FirstMplsLabels.size() == 0{
			return FALSE;
		};
		if !CompareExactLabels and FirstMplsLabels.size() > SecondMplsLabels.size(){
			return FALSE;
		};
		if CompareExactLabels and FirstMplsLabels.size() != SecondMplsLabels.size(){
			return FALSE;
		};
		for i from 0 to FirstMplsLabels.size()-1{
			if !MplsLabelMatch(FirstMplsLabels[i],SecondMplsLabels[i],(i<3)){
				return FALSE;
			};
		};
	};

	MplsLabelMatch(FirstMplsLabel : MPLSLabelStack,SecondMplsLabel : MPLSLabelStack,CompareExactLabel : bool):bool is also{
		result = TRUE;
		if FirstMplsLabel.BottomOfStack != SecondMplsLabel.BottomOfStack {
			return FALSE;
		};
		if CompareExactLabel {
			if FirstMplsLabel.TTL != SecondMplsLabel.TTL {
				return FALSE;
			};
			if FirstMplsLabel.TrafficClass != SecondMplsLabel.TrafficClass {
				return FALSE;
			};
			if FirstMplsLabel.Label != SecondMplsLabel.Label {
				return FALSE;
			};
		};
	};

	VlansMatch(FirstVlanList : list of MacInternalHeader,SecondVlanList : list of MacInternalHeader,CompareExactVlans : bool):bool is also{

		result = TRUE;
		if FirstVlanList.size() == 0{
			return FALSE;
		};
		if !CompareExactVlans and FirstVlanList.size() > SecondVlanList.size(){
			return FALSE;
		};
		if CompareExactVlans and FirstVlanList.size() != SecondVlanList.size(){
			return FALSE;
		};
		for i from 0 to FirstVlanList.size()-1{
			if !VlanMatch(FirstVlanList[i],SecondVlanList[i]){
				return FALSE;
			};
		};
	};

	VlanMatch(FirstVlan : MacInternalHeader,SecondVlan : MacInternalHeader):bool is also{
		result = TRUE;
		if FirstVlan.PCP != SecondVlan.PCP{
			return FALSE;
		};
		if FirstVlan.CFI_DEI != SecondVlan.CFI_DEI{
			return FALSE;
		};
		if FirstVlan.VlanID != SecondVlan.VlanID{
			return FALSE;
		};
	};

	CountEndNodesWithRequirements(SteeringNodeRequirements : SteeringNodeRequirements) : int is also {
		result = 0;
		var EndNodesWithRequirements : list of SteeringNode;
		for each (Tree) in UnicastFlowsList {
			EndNodesWithRequirements.add(Tree.GetAllChildren().all(it.Children.is_empty() and it.LevelInTree != 0 and MeetsRequirements(it, SteeringNodeRequirements)));
		};
		for each (EndNode) in EndNodesWithRequirements {
			if sys.GlobalVariables.PerformanceTest == None {
				result += EndNode.IsRssGroup() ? EndNode.RssDataBase.QpGvmiRssNumList.sort(it.QpNum).unique(it.QpNum).size() + 1 : 1; // in RSS + 1 for Father QP
			} else {
				result += EndNode.IsRssGroup() ? EndNode.RssDataBase.NumOfRssChildrenQps  : 1; // in RSS + 1 for Father QP
			};
		};
	};

	GetEndNodesWithRequirements(SteeringNodeRequirements : SteeringNodeRequirements) : list of SteeringNode is also {
		for each (Tree) in UnicastFlowsList{
			result.add(Tree.GetAllChildren().all(it.Children.is_empty() and it.LevelInTree != 0 and
					(SteeringNodeRequirements==NULL or MeetsRequirements(it, SteeringNodeRequirements))));
		};
	};

	GetEndNodes() : list of SteeringNode is also {
		result = GetEndNodesWithRequirements(NULL);
	};

	GetSteeringBranchesWithContextId(Gvmi : uint, ContextId : uint) : list of SteeringBranch is {
		var SteeringNodes : list of SteeringNode;
		for each (Tree) in UnicastFlowsList {
			SteeringNodes.add(Tree.GetAllChildren().all(it.Children.is_empty() and it.LevelInTree != 0 and
					it.QpAllocation != NULL and it.QpAllocation.ContextId == ContextId and it.QpAllocation.Gvmi == Gvmi));
		};
		for each (Node) in SteeringNodes {
			var SteeringBranch : SteeringBranch = new;
			SteeringBranch.SteeringBranch = Node.GetSteeringBranch();
			result.add(SteeringBranch);
		};
	};

	GetSteeringNodeWithContextId(Qp : QpContext) : list of SteeringNode is {
		for each (Tree) in {UnicastFlowsList;MulticastFlowsList} {
			if Tree.Gvmi == Qp.Gvmi and Tree.Port == Qp.PortParams.LocalPort {
				if Tree.IBSteeringMode == IbOnly {
					result.add(Tree.GetAllChildren().all(it.Children.is_empty() and it.LevelInTree != 0));
				} else {
					result.add(Tree.GetAllChildren().all(it.Children.is_empty() and it.LevelInTree != 0 and
							it.QpAllocation != NULL and (it.QpAllocation.ContextId == Qp.ContextId) and it.QpAllocation.Gvmi == Qp.Gvmi));
				};
			};
		};
	};

	GetUnicastTree(Port : uint,Gvmi : uint(bits:16)) : SteeringTree is also{
		result = UnicastFlowsList.first(it.Gvmi == Gvmi and it.Port == Port);
	};

	GetMulticastTree(Port : uint,Gvmi : uint(bits:16)) : SteeringTree is also{
		result = MulticastFlowsList.first(it.Gvmi == Gvmi and it.Port == Port);
	};

	MatchVlanPrio(Vlan: MacInternalHeader, VlanPrioRange: list of int, MatchCfi:bool=FALSE): bool is {
		if VlanPrioRange.is_empty() {
			DUTError(87432, "MatchVlanPrio got empty VlanPrioRange list!!!");
		};
		if MatchCfi {
			return %{Vlan.PCP,Vlan.CFI_DEI} in VlanPrioRange;
		} else {
			return Vlan.PCP in VlanPrioRange;
		};
	};

	MatchVlanData(Vlan: MacInternalHeader, VlanData: uint(bits:16), VlanValid: uint(bits:16)): bool is {
		if VlanValid[0:0]!=0  and Vlan.CFI_DEI != VlanData[0:0] { return FALSE; };
		if VlanValid[3:1]!=0  and Vlan.PCP     != VlanData[3:1] { return FALSE; };
		if VlanValid[15:4]!=0 and Vlan.VlanID  != VlanData[0:0] { return FALSE; };
		return TRUE;
	};

	PrintTrees(MulticastFlow : bool = FALSE) is {
		messagef(MEDIUM,"PrintTrees - %s - FlowGenerator.IBPortSteeringMode is %s",MulticastFlow ? "Multicast" : "Unicast",IBPortSteeringMode);
		if MulticastFlow {
			for each (Tree) in MulticastFlowsList {
				messagef(MEDIUM,"Tree %d: %s\n", index, Tree.AsAString()){
					Tree.RootNode.PrintMe();
				};
			};
		} else {
			for each (Tree) in UnicastFlowsList {
				messagef(MEDIUM,"Tree %d: %s\n", index, Tree.AsAString()){
					Tree.RootNode.PrintMe();
				};
			};
		};
	};

	PrintSteeringActions(MulticastFlow : bool = FALSE) is {
		messagef(MEDIUM,"PrintSteeringActions - %s - Steering Actions By NodeIndex",MulticastFlow ? "Multicast" : "Unicast") {
			if MulticastFlow {
				for each (Tree) in MulticastFlowsList {
					Tree.RootNode.PrintSteeringNodeActions();
				};
			} else {
				for each (Tree) in UnicastFlowsList {
					Tree.RootNode.PrintSteeringNodeActions();
				};
			};
		};
	};

	PrintEncapsulationPackets(MulticastFlow : bool = FALSE) is {
		messagef(MEDIUM,"PrintEncapsulationPackets - %s - Encapsulation Packets By NodeIndex\n",MulticastFlow ? "Multicast" : "Unicast") {
			if MulticastFlow {
				for each (Tree) in MulticastFlowsList {
					for each (EncapsulationNode) in Tree.GetAllChildren().all(it.SxSteeringModificationActions.SxModificationActionType.has(it in [Encapsulation,L3Encapsulation])) {
						outf("-------------------------------------------------------------\n");
						outf("Encapsulation Packet for NodeIndex=%s\n", EncapsulationNode.NodeIndex);
						EncapsulationNode.EncapsulationDataBase.Packet.PrintMe();
						outf("-------------------------------------------------------------\n");
					};
				};
			} else {
				for each (Tree) in UnicastFlowsList {
					for each (EncapsulationNode) in Tree.GetAllChildren().all(it.SxSteeringModificationActions.SxModificationActionType.has(it in [Encapsulation,L3Encapsulation])) {
						outf("-------------------------------------------------------------\n");
						outf("Encapsulation Packet for NodeIndex=%s\n", EncapsulationNode.NodeIndex);
						EncapsulationNode.EncapsulationDataBase.Packet.PrintMe();
						outf("-------------------------------------------------------------\n");
					};
				};
			};
		};
	};

	FillPffOKs(MulticastFlow : bool = FALSE) is {
		if MulticastFlow {
			for each (Tree) in MulticastFlowsList {
				var TreeNodesSorted : list of SteeringNode = Tree.GetAllChildren().sort_by_field(LevelInTree);
				for i from (TreeNodesSorted.size()-1) down to 0 {
					var Node : SteeringNode = TreeNodesSorted[i];
					if Node.Kind in [ETHERNET_NODE_KIND,DUMMY_STEERING_TYPE] {
						Node.FillNodePffOKs();
					};
				};
			};
		} else {
			for each (Tree) in UnicastFlowsList {
				var TreeNodesSorted : list of SteeringNode = Tree.GetAllChildren().sort_by_field(LevelInTree);
				for i from (TreeNodesSorted.size()-1) down to 0 {
					var Node : SteeringNode = TreeNodesSorted[i];
					if Node.Kind in [ETHERNET_NODE_KIND,DUMMY_STEERING_TYPE] {
						Node.FillNodePffOKs();
					};
				};
			};
		};
	};

	BuildMplsLabelFromSteeringEntry(SteeringEntry : SteeringEntry,InnerMpls : bool) : list of MPLSLabelStack is{
		var PackedMplsLabel : uint;
		if HANDLERS(Steering).GetSteeringLookupParamsMplsQualifier(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,0x0,InnerMpls) {
			PackedMplsLabel = HANDLERS(Steering).GetSteeringLookupParamsMplsLabel(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,0x0,InnerMpls);
			var MplsLabel : MPLSLabelStack = new with{
				.Label = PackedMplsLabel[31:12];
				.TrafficClass = PackedMplsLabel[11:9];
				.BottomOfStack = PackedMplsLabel[8:8];
				.TTL = PackedMplsLabel[7:0];
			};
			result.add(MplsLabel);
		};
		if HANDLERS(Steering).GetSteeringLookupParamsMplsQualifier(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,0x1,InnerMpls) {
			PackedMplsLabel = HANDLERS(Steering).GetSteeringLookupParamsMplsLabel(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,0x1,InnerMpls);
			var MplsLabel : MPLSLabelStack = new with{
				.Label = PackedMplsLabel[31:12];
				.TrafficClass = PackedMplsLabel[11:9];
				.BottomOfStack = PackedMplsLabel[8:8];
				.TTL = PackedMplsLabel[7:0];
			};
			result.add(MplsLabel);
		};
		if HANDLERS(Steering).GetSteeringLookupParamsMplsQualifier(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,0x2,InnerMpls) {
			PackedMplsLabel = HANDLERS(Steering).GetSteeringLookupParamsMplsLabel(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,0x2,InnerMpls);
			var MplsLabel : MPLSLabelStack = new with{
				.Label = PackedMplsLabel[31:12];
				.TrafficClass = PackedMplsLabel[11:9];
				.BottomOfStack = PackedMplsLabel[8:8];
				.TTL = PackedMplsLabel[7:0];
			};
			result.add(MplsLabel);
		};
		if HANDLERS(Steering).GetSteeringLookupParamsMplsQualifier(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,0x3,InnerMpls) {
			PackedMplsLabel = HANDLERS(Steering).GetSteeringLookupParamsMplsLabel(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,0x3,InnerMpls);
			var MplsLabel : MPLSLabelStack = new with{
				.Label = PackedMplsLabel[31:12];
				.TrafficClass = PackedMplsLabel[11:9];
				.BottomOfStack = PackedMplsLabel[8:8];
				.TTL = PackedMplsLabel[7:0];
			};
			result.add(MplsLabel);
		};
		if HANDLERS(Steering).GetSteeringLookupParamsMplsQualifier(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,0x4,InnerMpls) {
			PackedMplsLabel = HANDLERS(Steering).GetSteeringLookupParamsMplsLabel(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,0x4,InnerMpls);
			var MplsLabel : MPLSLabelStack = new with{
				.Label = PackedMplsLabel[31:12];
				.TrafficClass = PackedMplsLabel[11:9];
				.BottomOfStack = PackedMplsLabel[8:8];
				.TTL = PackedMplsLabel[7:0];
			};
			result.add(MplsLabel);
		};
	};

	BuildMacInternalHeaderFromSteeringEntry(SteeringEntry : SteeringEntry, InnerVlan : bool) : list of MacInternalHeader is{
		if HANDLERS(Steering).GetSteeringLookupParamsVlanQualifier(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE,InnerVlan) != NoVlan {
			var MacInternalHeader : MacInternalHeader = new with{
				.PCP = HANDLERS(Steering).GetSteeringLookupParamsVlanPrio(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE,InnerVlan);
				.CFI_DEI = HANDLERS(Steering).GetSteeringLookupParamsVlanCFI(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE,InnerVlan);
				.VlanID = HANDLERS(Steering).GetSteeringLookupParamsVlanId(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE,InnerVlan);
			};
			result.add(MacInternalHeader);
		};
		if HANDLERS(Steering).GetSteeringLookupParamsVlanQualifier(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,TRUE,InnerVlan) != NoVlan {
			var MacInternalHeader : MacInternalHeader = new with{
				.PCP = HANDLERS(Steering).GetSteeringLookupParamsVlanPrio(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,TRUE,InnerVlan);
				.CFI_DEI = HANDLERS(Steering).GetSteeringLookupParamsVlanCFI(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,TRUE,InnerVlan);
				.VlanID = HANDLERS(Steering).GetSteeringLookupParamsVlanId(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,TRUE,InnerVlan);
			};
			result.add(MacInternalHeader);
		};
	};

	SystemWithIpsecFlows() : bool is also {
		for each (Tree) in {UnicastFlowsList;MulticastFlowsList} {
			if Tree.GetAllChildren().has(it.RxIPSecHostType != None or it.SxIPSecHostType != None) {
				return TRUE;
			};
		};
	};
};

extend SteeringTree{
	GetXoIBNodesKind() : list of SteeringType is {
		if IBSteeringMode == IpoIbOnly and IpoIBType == IPv4Dst {
			return {Ipv4Dst};
		} else if IBSteeringMode == IpoIbOnly and IpoIBType == IPv4Src {
			return {Ipv4Src};
		} else if IBSteeringMode == IpoIbOnly and IpoIBType == IPv45Tuple {
			return {Ipv4_5Tuple};
		} else if IBSteeringMode == IpoIbOnly and IpoIBType == IPv6Dst {
			return {Ipv6Dst};
		} else if IBSteeringMode == IpoIbOnly and IpoIBType == IPv6Src {
			return {Ipv6Src};
		};
	};

	GetAllXoIBNodes() : list of SteeringNode is {
		var XoIBChildren : list of SteeringNode;
		if IBSteeringMode == IpoIbOnly and IpoIBType == IPv4Dst {
			XoIBChildren = GetAllChildren().all(it.IBSteeringMode == IpoIbOnly and it.Kind in [Ipv4Dst]);
		} else if IBSteeringMode == IpoIbOnly and IpoIBType == IPv4Src {
			XoIBChildren = GetAllChildren().all(it.IBSteeringMode == IpoIbOnly and it.Kind in [Ipv4Src]);
		} else if IBSteeringMode == IpoIbOnly and IpoIBType == IPv45Tuple {
			XoIBChildren = GetAllChildren().all(it.IBSteeringMode == IpoIbOnly and it.Kind in [Ipv4_5Tuple]);
		} else if IBSteeringMode == IpoIbOnly and IpoIBType == IPv6Dst {
			XoIBChildren = GetAllChildren().all(it.IBSteeringMode == IpoIbOnly and it.Kind in [Ipv6Dst]);
		} else if IBSteeringMode == IpoIbOnly and IpoIBType == IPv6Src {
			XoIBChildren = GetAllChildren().all(it.IBSteeringMode == IpoIbOnly and it.Kind in [Ipv6Src]);
		};
		XoIBChildren = XoIBChildren.all(it.LevelInTree == XoIBChildren.LevelInTree.min(it));
		return XoIBChildren;
	};

	GetAllChildren() : list of SteeringNode is {
		return ListOfNodes;
	};

	ConfigAllowedPrio() is {
		var ConfigRequirements : ConfigRequirements = new;
		ConfigRequirements.PortNum = Port;
		ConfigRequirements.GvmiNum = Gvmi;
		AllowedPrios = HANDLERS(Config).GetAllowedPrio(ConfigRequirements);
	};

	PrintMe() is {
		outf("%s\n", AsAString());
		RootNode.PrintMe();
	};

	AsAString() : string is {
		result = appendf("Tree Gvmi=%s, Port=%s, NumOfRootChildren=%s, IBSteeringMode = %s, IpoIBType = %s,",Gvmi,Port,NumOfRootChildren,IBSteeringMode,IpoIBType);
	};

	IsTreeOnParentGvmi() : bool is {
		var ConfigRequirements : ConfigRequirements = new with {
			.PortNum = Port;
			.GvmiNum = Gvmi;
		};
		var GvmiContext : GvmiContext = HANDLERS(Config).GetGvmiContext(ConfigRequirements);
		return (GvmiContext.GvmiType == Parent);
	};

};

extend SteeringNode{
	FillNodePffOKs() is {
		PffOKs = new;
		if not HANDLERS(LocalQp).FlowGenerator.ClosePFFGeneration {
			var L3Children : list of SteeringNode;
			var L4Children : list of SteeringNode;
			case (Kind) {
				Mac : {
					PffOKs.L2OK = TRUE;
					L3Children = Children.all((it.Kind in [Vlan,Mpls,Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4, Ipv4Dst, Ipv4Src]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]));
					L4Children = Children.all((it.Kind in [Vlan,Mpls,Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4, Ipv4Dst, Ipv4Src, L4Only]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]));
					PffOKs.L3OK = L3Children.is_empty() ? FALSE : L3Children.and_all(it.PffOKs.L3OK);
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				Vlan : {
					PffOKs.L2OK = TRUE;
					L3Children = Children.all((it.Kind in [Vlan,Mpls,Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4, Ipv4Dst, Ipv4Src]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]));
					L4Children = Children.all((it.Kind in [Vlan,Mpls,Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4, Ipv4Dst, Ipv4Src, L4Only]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]));
					PffOKs.L3OK = L3Children.is_empty() ? FALSE : L3Children.and_all(it.PffOKs.L3OK);
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				Mpls : {
					PffOKs.L2OK = (IBSteeringMode == None);
					L3Children = Children.all((it.Kind in [Vlan,Mpls,Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4, Ipv4Dst, Ipv4Src]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]));
					L4Children = Children.all((it.Kind in [Vlan,Mpls,Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4, Ipv4Dst, Ipv4Src, L4Only]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]));
					PffOKs.L3OK = L3Children.is_empty() ? FALSE : L3Children.and_all(it.PffOKs.L3OK);
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				Ipv4_5Tuple : {
					PffOKs.L2OK = (IBSteeringMode == None);
					PffOKs.L3OK = TRUE;
					L4Children = Children.all((it.Kind in [Vlan,Mpls,Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4, Ipv4Dst, Ipv4Src, L4Only]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]));
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				Ipv6Dst : {
					PffOKs.L2OK = (IBSteeringMode == None);
					PffOKs.L3OK = TRUE;
					L4Children = Children.all((it.Kind in [Vlan,Mpls,Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4, Ipv4Dst, Ipv4Src, L4Only]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]));
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				Ipv6Src : {
					PffOKs.L2OK = (IBSteeringMode == None);
					PffOKs.L3OK = TRUE;
					L4Children = Children.all((it.Kind in [Vlan,Mpls,Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4, Ipv4Dst, Ipv4Src, L4Only]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]));
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				Ipv4Dst : {
					PffOKs.L2OK = (IBSteeringMode == None);
					PffOKs.L3OK = TRUE;
					L4Children = Children.all((it.Kind in [Vlan,Mpls,Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4, Ipv4Dst, Ipv4Src, L4Only]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]));
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				Ipv4Src : {
					PffOKs.L2OK = (IBSteeringMode == None);
					PffOKs.L3OK = TRUE;
					L4Children = Children.all((it.Kind in [Vlan,Mpls,Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4, Ipv4Dst, Ipv4Src, L4Only]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]));
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				Ipv6L4 : {
					PffOKs.L2OK = (IBSteeringMode == None);
					L3Children = Children.all((it.Kind in [Vlan,Mpls,Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4, Ipv4Dst, Ipv4Src, L4Only]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]));
					PffOKs.L3OK = L3Children.is_empty() ? FALSE : L3Children.and_all(it.PffOKs.L3OK);
					PffOKs.L4OK = TRUE;
				};
				L4Only : {
					PffOKs.L2OK = (IBSteeringMode == None);
					L3Children = Children.all((it.Kind in [Vlan,Mpls,Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4, Ipv4Dst, Ipv4Src, Ipv6L4]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]));
					PffOKs.L3OK = L3Children.is_empty() ? FALSE : L3Children.and_all(it.PffOKs.L3OK);
					PffOKs.L4OK = TRUE;
				};
				MacByDecap : {
					PffOKs.L2OK = TRUE;
					L3Children = Children.all((it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4,Ipv4Dst,Ipv4Src,Vlan,Mpls]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src]));
					L4Children = Children.all((it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap,L4OnlyByDecap]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4,Ipv4Dst,Ipv4Src,L4Only,Vlan,Mpls]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src,InnerL4Only]));
					PffOKs.L3OK = L3Children.is_empty() ? FALSE : L3Children.and_all(it.PffOKs.L3OK);
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				MplsByDecap : {
					PffOKs.L2OK = (IBSteeringMode == None) and SteeringNodeInL2DecapsulationEnabledFlow(TRUE);
					L3Children = Children.all((it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4,Ipv4Dst,Ipv4Src,Vlan,Mpls]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src]));
					L4Children = Children.all((it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap,L4OnlyByDecap]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4,Ipv4Dst,Ipv4Src,L4Only,Vlan,Mpls]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src,InnerL4Only]));
					PffOKs.L3OK = L3Children.is_empty() ? FALSE : L3Children.and_all(it.PffOKs.L3OK);
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				Ipv4_5TupleByDecap : {
					PffOKs.L2OK = (IBSteeringMode == None) and SteeringNodeInL2DecapsulationEnabledFlow(TRUE);
					PffOKs.L3OK = TRUE;
					L4Children = Children.all((it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap,L4OnlyByDecap]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4,Ipv4Dst,Ipv4Src,L4Only,Vlan,Mpls]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src,InnerL4Only]));
					PffOKs.L4OK = L4Children.is_empty() ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				Ipv6DstByDecap : {
					PffOKs.L2OK = (IBSteeringMode == None) and SteeringNodeInL2DecapsulationEnabledFlow(TRUE);
					PffOKs.L3OK = TRUE;
					L4Children = Children.all((it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap,L4OnlyByDecap]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4,Ipv4Dst, Ipv4Src,L4Only,Vlan,Mpls]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src,InnerL4Only]));
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				Ipv6SrcByDecap : {
					PffOKs.L2OK = (IBSteeringMode == None) and SteeringNodeInL2DecapsulationEnabledFlow(TRUE);
					PffOKs.L3OK = TRUE;
					L4Children = Children.all((it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap,L4OnlyByDecap]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4,Ipv4Dst,Ipv4Src,L4Only,Vlan,Mpls]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src,InnerL4Only]));
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				Ipv6L4ByDecap : {
					PffOKs.L2OK = (IBSteeringMode == None) and SteeringNodeInL2DecapsulationEnabledFlow(TRUE);
					L3Children = Children.all((it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4,Ipv4Dst,Ipv4Src,Vlan,Mpls]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src]));
					PffOKs.L3OK = L3Children.is_empty() ? FALSE : L3Children.and_all(it.PffOKs.L3OK);
					PffOKs.L4OK = TRUE;
				};
				L4OnlyByDecap : {
					PffOKs.L2OK = (IBSteeringMode == None) and SteeringNodeInL2DecapsulationEnabledFlow(TRUE);
					L3Children = Children.all((it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4,Ipv4Dst,Ipv4Src,Vlan,Mpls]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src]));
					PffOKs.L3OK = L3Children.is_empty() ? FALSE : L3Children.and_all(it.PffOKs.L3OK);
					PffOKs.L4OK = TRUE;
				};
				Ipv4DstByDecap : {
					PffOKs.L2OK = (IBSteeringMode == None) and SteeringNodeInL2DecapsulationEnabledFlow(TRUE);
					PffOKs.L3OK = TRUE;
					L4Children = Children.all((it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap,L4OnlyByDecap]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4,Ipv4Dst, Ipv4Src,L4Only,Vlan,Mpls]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src,InnerL4Only]));
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				Ipv4SrcByDecap : {
					PffOKs.L2OK = (IBSteeringMode == None) and SteeringNodeInL2DecapsulationEnabledFlow(TRUE);
					PffOKs.L3OK = TRUE;
					L4Children = Children.all((it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap,L4OnlyByDecap]) or
						((not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and it.Kind in [Ipv4_5Tuple,Ipv6Dst,Ipv6Src,Ipv6L4,Ipv4Dst, Ipv4Src,L4Only,Vlan,Mpls]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src,InnerL4Only]));
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				InnerMac : {
					PffOKs.L2OK = TRUE;
					L3Children = Children.all((it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]));
					L4Children = Children.all((it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src,InnerL4Only]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap,L4OnlyByDecap]));
					PffOKs.L3OK = L3Children.is_empty() ? FALSE : L3Children.and_all(it.PffOKs.L3OK);
					PffOKs.L4OK = L4Children.is_empty() ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				InnerVlan : {
					PffOKs.L2OK = TRUE;
					L3Children = Children.all((it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]));
					L4Children = Children.all((it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src,InnerL4Only]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap,L4OnlyByDecap]));
					PffOKs.L3OK = L3Children.is_empty() ? FALSE : L3Children.and_all(it.PffOKs.L3OK);
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				InnerMpls : {
					PffOKs.L2OK = (IBSteeringMode == None) and SteeringNodeInL2DecapsulationEnabledFlow(TRUE);
					L3Children = Children.all((it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]));
					L4Children = Children.all((it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src,InnerL4Only]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap,L4OnlyByDecap]));
					PffOKs.L3OK = L3Children.is_empty() ? FALSE : L3Children.and_all(it.PffOKs.L3OK);
					PffOKs.L4OK = L4Children.is_empty() ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				InnerIpv4_5Tuple : {
					PffOKs.L2OK = (IBSteeringMode == None) and SteeringNodeInL2DecapsulationEnabledFlow(TRUE);
					PffOKs.L3OK = TRUE;
					L4Children = Children.all((it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src,InnerL4Only]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap,L4OnlyByDecap]));
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				InnerIpv6Dst : {
					PffOKs.L2OK = (IBSteeringMode == None) and SteeringNodeInL2DecapsulationEnabledFlow(TRUE);
					PffOKs.L3OK = TRUE;
					L4Children = Children.all((it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src,InnerL4Only]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap,L4OnlyByDecap]));
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				InnerIpv6Src : {
					PffOKs.L2OK = (IBSteeringMode == None) and SteeringNodeInL2DecapsulationEnabledFlow(TRUE);
					PffOKs.L3OK = TRUE;
					L4Children = Children.all((it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src,InnerL4Only]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap,L4OnlyByDecap]));
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				InnerIpv6L4 : {
					PffOKs.L2OK = (IBSteeringMode == None) and SteeringNodeInL2DecapsulationEnabledFlow(TRUE);
					L3Children = Children.all((it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]));
					PffOKs.L3OK = L3Children.is_empty() ? FALSE : L3Children.and_all(it.PffOKs.L3OK);
					PffOKs.L4OK = TRUE;
				};
				InnerL4Only : {
					PffOKs.L2OK = (IBSteeringMode == None) and SteeringNodeInL2DecapsulationEnabledFlow(TRUE);
					L3Children = Children.all((it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]));
					PffOKs.L3OK = L3Children.is_empty() ? FALSE : L3Children.and_all(it.PffOKs.L3OK);
					PffOKs.L4OK = TRUE;
				};
				InnerIpv4Dst : {
					PffOKs.L2OK = (IBSteeringMode == None) and SteeringNodeInL2DecapsulationEnabledFlow(TRUE);
					PffOKs.L3OK = TRUE;
					L4Children = Children.all((it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src,InnerL4Only]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap,L4OnlyByDecap]));
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				InnerIpv4Src: {
					PffOKs.L2OK = (IBSteeringMode == None) and SteeringNodeInL2DecapsulationEnabledFlow(TRUE);
					PffOKs.L3OK = TRUE;
					L4Children = Children.all((it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src,InnerL4Only]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap,L4OnlyByDecap]));
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				TunnelType : {
					PffOKs.L2OK = SteeringNodeInL2DecapsulationEnabledFlow(TRUE);
					L3Children = Children.all((it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap]));
					L4Children = Children.all((it.Kind in [InnerMpls,InnerVlan,TunnelType,InnerIpv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv6L4,InnerIpv4Dst,InnerIpv4Src,InnerL4Only]) or
						(it.SteeringNodeInDecapsulationEnabledFlow(FALSE) and it.Kind in [MplsByDecap,Ipv4_5TupleByDecap,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv6L4ByDecap, Ipv4DstByDecap, Ipv4SrcByDecap,L4OnlyByDecap]));
					PffOKs.L3OK = L3Children.is_empty() ? FALSE : L3Children.and_all(it.PffOKs.L3OK);
					PffOKs.L4OK = (L4Children.is_empty() or SteeringNodeHasIpsecActions(BOTH)) ? FALSE : L4Children.and_all(it.PffOKs.L4OK);
				};
				[DestQp,EndOfTree,Ethertype,Gid,IbL4,InnerL4Only,L4Only,Lid,Root,SrcGvmiQp,Tcp,Udp] : {};
				default : {};
			};
		};
	};

	PrintSteeringNodeActions() is also {
		outf("Steering Actions for NodeIndex=%s\n",NodeIndex);
		outf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
		outf("------------------- Rx Inline Steering Actions ---------------------\n");
		if WithRxInlineAction {
			for each (RxInlineAction) in RxSteeringInlineActions {
				RxInlineAction.PrintMe(RX);
			};
		};
		outf("--------------------------------------------------------------------\n");
		outf("------------------- Rx Modification Steering Actions ---------------------\n");
		if WithRxModificationActions {
			for each (RxModificationAction) in RxSteeringModificationActions {
				RxModificationAction.PrintMe(RX);
			};
		};
		outf("--------------------------------------------------------------------------\n");
		outf("------------------- Sx Inline Steering Actions ---------------------\n");
		if WithSxInlineAction {
			for each (SxInlineAction) in SxSteeringInlineActions {
				SxInlineAction.PrintMe(SX);
			};
		};
		outf("--------------------------------------------------------------------\n");
		outf("------------------- Sx Modification Steering Actions ---------------------\n");
		if WithSxModificationActions {
			for each (SxModificationAction) in SxSteeringModificationActions {
				SxModificationAction.PrintMe(SX);
			};
		};
		outf("--------------------------------------------------------------------------\n");
		outf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
		for each (Child) in Children {
			Child.PrintSteeringNodeActions();
		};
	};

	GetAllChildren() : list of SteeringNode is {
		result.add(Children);
		for each (Child) in Children{
			result.add(Child.GetAllChildren());
		};
	};

	SteeringNodeInDecapsulationEnabledFlow(CheckMeAlso : bool = FALSE) : bool is also {
		for each (Parent) in ParentNodes {
			if Parent.RxSteeringModificationActions.RxModificationActionType.has(it in [DecapEnable,L3DecapEnable]) {
				return TRUE;
			};
		};
		if CheckMeAlso {
			return RxSteeringModificationActions.RxModificationActionType.has(it in [DecapEnable,L3DecapEnable]);
		};
	};

	SteeringNodeInL2DecapsulationEnabledFlow(CheckMeAlso : bool = FALSE) : bool is also {
		for each (Parent) in ParentNodes {
			if Parent.RxSteeringModificationActions.RxModificationActionType.has(it  in [DecapEnable]) {
				return TRUE;
			};
		};
		if CheckMeAlso {
			if {RoceOverVXLAN;ParentNodes.RoceOverVXLAN}.has(it == TRUE) {
				return TRUE;
			};
			return RxSteeringModificationActions.RxModificationActionType.has(it in [DecapEnable]);
		};
	};

	SteeringNodeInL3DecapsulationEnabledFlow(CheckMeAlso : bool = FALSE) : bool is also {
		for each (Parent) in ParentNodes {
			if Parent.RxSteeringModificationActions.RxModificationActionType.has(it in [L3DecapEnable]) {
				return TRUE;
			};
		};
		if CheckMeAlso {
			return RxSteeringModificationActions.RxModificationActionType.has(it in [L3DecapEnable]);
		};
	};

	SteeringNodeInEncapsulationEnabledFlow(CheckMeAlso : bool = FALSE) : bool is also {
		for each (Parent) in ParentNodes {
			if Parent.SxSteeringModificationActions.SxModificationActionType.has(it in [Encapsulation,L3Encapsulation]) {
				return TRUE;
			};
		};
		if CheckMeAlso {
			return SxSteeringModificationActions.SxModificationActionType.has(it in [Encapsulation,L3Encapsulation]);
		};
	};

	SteeringNodeInL2EncapsulationEnabledFlow(CheckMeAlso : bool = FALSE) : bool is also {
		for each (Parent) in ParentNodes {
			if Parent.SxSteeringModificationActions.SxModificationActionType.has(it in [Encapsulation]) {
				return TRUE;
			};
		};
		if CheckMeAlso {
			return SxSteeringModificationActions.SxModificationActionType.has(it in [Encapsulation]);
		};
	};

	SteeringNodeInL3EncapsulationEnabledFlow(CheckMeAlso : bool = FALSE) : bool is also {
		for each (Parent) in ParentNodes {
			if Parent.SxSteeringModificationActions.SxModificationActionType.has(it in [L3Encapsulation]) {
				return TRUE;
			};
		};
		if CheckMeAlso {
			return SxSteeringModificationActions.SxModificationActionType.has(it in [L3Encapsulation]);
		};
	};

	KindForSteeringParams() : SteeringType is {
		case Kind {
			Ipv6DstByDecap : {
				if SteeringNodeInDecapsulationEnabledFlow() {
					return InnerIpv6Dst;
				} else {
					return Ipv6Dst;
				};
			};
			Ipv6L4ByDecap : {
				if SteeringNodeInDecapsulationEnabledFlow() {
					return InnerIpv6L4;
				} else {
					return Ipv6L4;
				};
			};
			Ipv6SrcByDecap : {
				if SteeringNodeInDecapsulationEnabledFlow() {
					return InnerIpv6Src;
				} else {
					return Ipv6Src;
				};
			};
			Ipv4DstByDecap : {
				if SteeringNodeInDecapsulationEnabledFlow() {
					return InnerIpv4Dst;
				} else {
					return Ipv4Dst;
				};
			};
			L4OnlyByDecap : {
				if SteeringNodeInDecapsulationEnabledFlow() {
					return InnerL4Only;
				} else {
					return L4Only;
				};
			};
			Ipv4SrcByDecap : {
				if SteeringNodeInDecapsulationEnabledFlow() {
					return InnerIpv4Src;
				} else {
					return Ipv4Src;
				};
			};
			Ipv4_5TupleByDecap : {
				if SteeringNodeInDecapsulationEnabledFlow() {
					return InnerIpv4_5Tuple;
				} else {
					return Ipv4_5Tuple;
				};
			};
			MacByDecap : {
				if SteeringNodeInDecapsulationEnabledFlow() {
					return InnerMac;
				} else {
					return Mac;
				};
			};
			MplsByDecap : {
				if SteeringNodeInDecapsulationEnabledFlow() {
					return InnerMpls;
				} else {
					return Mpls;
				};
			};
			EspByDecap : {
				if SteeringNodeInDecapsulationEnabledFlow() {
					return InnerEsp;
				} else {
					return Esp;
				};
			};
			VlanByDecap : {
				if SteeringNodeInDecapsulationEnabledFlow() {
					return InnerVlan;
				} else {
					return Vlan;
				};
			};
			default : {
				return Kind;
			};
		};
	};
	IsRssGroup() : bool is also {
		return RssMode == RssGroup;
	};
	BuildSteerigParamsForRssFromNode() : SteeringParams is also {
		var SteeringParams = new;
		var SteeringBranch : list of SteeringNode = GetSteeringBranch();
		//SteeringEndNode.UpdateSteeringParamActions(SteeringParams);
		SteeringParams.L2DecapsulationEnable = SteeringNodeInL2DecapsulationEnabledFlow(TRUE);
		SteeringParams.L3DecapsulationEnable = SteeringNodeInL3DecapsulationEnabledFlow(TRUE);
		SteeringParams.L2EncapsulationEnable = SteeringNodeInL2DecapsulationEnabledFlow(TRUE);
		SteeringParams.L3EncapsulationEnable = SteeringNodeInL3EncapsulationEnabledFlow(TRUE);
		//SteeringParams.InnerSteeringParams.L3DecapsulationEnable = SteeringNodeInL3DecapsulationEnabledFlow(TRUE);
		SteeringParams.TunnelingEnable = SteeringBranch.TunnelingEnable.has(it == TRUE);
		for each (Node) in SteeringBranch.all(it.Kind not in [WredMask]) {
			if Node.Kind not in [DUMMY_STEERING_TYPE,STEERING_REGISTER_TYPES] {
				case Node.KindForSteeringParams() {
					Mac : {
						SteeringParams.Mac = Node.FieldValue;
						if Node.IsRoce {
							SteeringParams.RoCEOverL2 = TRUE;
						};
					};
					Ipv6Dst : {
						SteeringParams.Ipv6ValueType = Node.ValueType;
						SteeringParams.Ipv6DestAddress = Node.FieldValue;
						if Node.IsRoce{
							SteeringParams.RoceOverIp = TRUE;
						};
					};
					Ipv6Src : {
						SteeringParams.Ipv6ValueType = Node.ValueType;
						SteeringParams.Ipv6SrcAddress = Node.FieldValue;
						if Node.IsRoce{
							SteeringParams.RoceOverIp = TRUE;
						};
					};
					Ipv4_5Tuple : {
						SteeringParams.Ipv4ValueType = Node.ValueType;
						SteeringParams.TcpUdpValueType = Node.ValueType;
						SteeringParams.SourcePortValueType = Node.ValueType;
						SteeringParams.DestPortValueType = Node.ValueType;
						SteeringParams.Ipv4DestAddress = Node.FieldValue[127:96];
						SteeringParams.Ipv4SrcAddress = Node.FieldValue[95:64];
						SteeringParams.SourcePort = Node.FieldValue[63:48];
						SteeringParams.DestPort = Node.FieldValue[47:32];
						if Node.IsRoce{
							SteeringParams.RoCEOverUdp = TRUE;
						};
					};
					Ipv6L4 : {
						SteeringParams.TcpUdpValueType = Node.ValueType;
						SteeringParams.SourcePortValueType = Node.ValueType;
						SteeringParams.DestPortValueType = Node.ValueType;
						SteeringParams.SourcePort = Node.FieldValue[79:64];
						SteeringParams.DestPort = Node.FieldValue[111:96];
						if Node.IsRoce{
							SteeringParams.RoCEOverUdp = TRUE;
						};
					};
					Ipv4Dst : {
						SteeringParams.Ipv4ValueType = Node.ValueType;
						SteeringParams.Ipv4DestAddress = Node.FieldValue;
						if Node.IsRoce{
							SteeringParams.RoceOverIp = TRUE;
						};
					};
					Ipv4Src : {
						SteeringParams.Ipv4ValueType = Node.ValueType;
						SteeringParams.Ipv4SrcAddress = Node.FieldValue;
						if Node.IsRoce{
							SteeringParams.RoceOverIp = TRUE;
						};
					};
					L4Only : {
						SteeringParams.TcpUdpValueType = Node.ValueType;
						SteeringParams.SourcePortValueType = Node.ValueType;
						SteeringParams.DestPortValueType = Node.ValueType;
						SteeringParams.SourcePort = Node.FieldValue[79:64];
						SteeringParams.DestPort = Node.FieldValue[111:96];
						if Node.IsRoce{
							SteeringParams.RoCEOverUdp = TRUE;
						};
					};
					TunnelType : {
						SteeringParams.SteeringTunnelType = Node.SteeringTunnelType;
						SteeringParams.L2TunnelingNetworkId = Node.FieldValue[63:32];
					};
					InnerMac : {
						if SteeringParams.InnerSteeringParams == NULL {
							SteeringParams.InnerSteeringParams = new;
						};
						SteeringParams.InnerSteeringParams.Mac = Node.FieldValue;
					};
					InnerIpv6Dst : {
						if SteeringParams.InnerSteeringParams == NULL {
							SteeringParams.InnerSteeringParams = new;
						};
						SteeringParams.InnerSteeringParams.Ipv6ValueType = Node.ValueType;
						SteeringParams.InnerSteeringParams.Ipv6DestAddress = Node.FieldValue;
					};
					InnerIpv6Src : {
						if SteeringParams.InnerSteeringParams == NULL {
							SteeringParams.InnerSteeringParams = new;
						};
						SteeringParams.InnerSteeringParams.Ipv6ValueType = Node.ValueType;
						SteeringParams.InnerSteeringParams.Ipv6SrcAddress = Node.FieldValue;
					};
					InnerIpv4_5Tuple : {
						if SteeringParams.InnerSteeringParams == NULL {
							SteeringParams.InnerSteeringParams = new;
						};
						SteeringParams.InnerSteeringParams.Ipv4ValueType = Node.ValueType;
						SteeringParams.InnerSteeringParams.TcpUdpValueType = Node.ValueType;
						SteeringParams.InnerSteeringParams.SourcePortValueType = Node.ValueType;
						SteeringParams.InnerSteeringParams.DestPortValueType = Node.ValueType;
						SteeringParams.InnerSteeringParams.Ipv4DestAddress = Node.FieldValue[127:96];
						SteeringParams.InnerSteeringParams.Ipv4SrcAddress = Node.FieldValue[95:64];
						SteeringParams.InnerSteeringParams.SourcePort = Node.FieldValue[63:48];
						SteeringParams.InnerSteeringParams.DestPort = Node.FieldValue[47:32];
					};
					InnerIpv6L4 : {
						if SteeringParams.InnerSteeringParams == NULL {
							SteeringParams.InnerSteeringParams = new;
						};
						SteeringParams.InnerSteeringParams.TcpUdpValueType = Node.ValueType;
						SteeringParams.InnerSteeringParams.SourcePortValueType = Node.ValueType;
						SteeringParams.InnerSteeringParams.DestPortValueType = Node.ValueType;
						SteeringParams.InnerSteeringParams.SourcePort = Node.FieldValue[79:64];
						SteeringParams.InnerSteeringParams.DestPort = Node.FieldValue[111:96];
					};
					InnerIpv4Dst : {
						if SteeringParams.InnerSteeringParams == NULL {
							SteeringParams.InnerSteeringParams = new;
						};
						SteeringParams.InnerSteeringParams.Ipv4ValueType = Node.ValueType;
						SteeringParams.InnerSteeringParams.Ipv4DestAddress = Node.FieldValue;
					};
					InnerIpv4Src : {
						if SteeringParams.InnerSteeringParams == NULL {
							SteeringParams.InnerSteeringParams = new;
						};
						SteeringParams.InnerSteeringParams.Ipv4ValueType = Node.ValueType;
						SteeringParams.InnerSteeringParams.Ipv4SrcAddress = Node.FieldValue;
					};
					InnerL4Only : {
						if SteeringParams.InnerSteeringParams == NULL {
							SteeringParams.InnerSteeringParams = new;
						};
						SteeringParams.InnerSteeringParams.TcpUdpValueType = Node.ValueType;
						SteeringParams.InnerSteeringParams.SourcePortValueType = Node.ValueType;
						SteeringParams.InnerSteeringParams.DestPortValueType = Node.ValueType;
						SteeringParams.InnerSteeringParams.SourcePort = Node.FieldValue[79:64];
						SteeringParams.InnerSteeringParams.DestPort = Node.FieldValue[111:96];
					};
				};
			};
		};
		return SteeringParams;
	};
	IsRoce() : bool is {
		return IsRoce and Children.is_empty();
	};

	IsHairPin() : bool is {
		return (HairPinMode in [EthHairPin, BridgeHairPin]) and Children.is_empty();
	};

	IsIPoIBGW() : bool is {
		return HairPinMode in [IPoIBGW] and Children.is_empty();
	};

	HasRoCEQp(QpNum : uint):bool is {
	};

	ReWritePacketByNode(RssPkt : NetworkPacket,OnInner : bool = FALSE) : NetworkPacket is {
		result = deep_copy(RssPkt);
		var ReWriteNodes : list of SteeringNode = {me;ParentNodes}.all(it.SteeringNodeHasRewriteActions(RX)).sort(it.NodeIndex);
		for each (ReWriteNode) in ReWriteNodes {
			for each (Action) in ReWriteNode.RxSteeringModificationActions.all(it.RxModificationActionType in [Add,Set,Copy]).all(it.DstDwOffset not in [OUTER_DMAC_DEFINER_FIELDS,OUTER_SMAC_DEFINER_FIELDS,OUTER_VlANID_STEERING_DEFINER_FIELDS] and it.OnInnerPacket == OnInner) {
				Action.ApplyAction(result,Action.RxModificationActionType);
			};
		};
	};

	GetRssGvmi(Pkt : NetworkPacket):uint is also {
		var RssPkt : NetworkPacket = Pkt;
		if Pkt.TunnelType in [EthoIB,IPoIB] and Pkt.InnerPacket != NULL {
			RssPkt = Pkt.InnerPacket;
		};
		var SteeringParams : SteeringParams = new;
		var RssDataBase : RssDataBase = HANDLERS(LocalQp).FlowGenerator.RssDataBaseList.first(it.RssIndex == RssIndex);
		var HashResult : uint;
		if (RssDataBase.RssSubType == ToplitzInner or (RssDataBase.RssSubType == ToplitzByDecap and SteeringNodeInDecapsulationEnabledFlow(TRUE))) and RssPkt.InnerPacket == NULL{
			DUTError(2541,appendf("RssDataBase with index %s has RssSubType = %s in DecapsulatedPacket = %s but inner packet is null",RssIndex,RssDataBase.RssSubType,SteeringNodeInDecapsulationEnabledFlow(TRUE)));
		};
		if (RssDataBase.RssSubType == ToplitzInner or (RssDataBase.RssSubType == ToplitzByDecap and SteeringNodeInDecapsulationEnabledFlow(TRUE))) {
			var ReWritedPacket : NetworkPacket = ReWritePacketByNode(RssPkt.InnerPacket,TRUE);
			HANDLERS(LocalQp).FlowGenerator.BuildSteeringParamsFromPacket(SteeringParams,ReWritedPacket);
			HashResult = HANDLERS(LocalQp).FlowGenerator.CalcRssHash(RssDataBase,SteeringParams);
		}else{
			var ReWritedPacket : NetworkPacket = ReWritePacketByNode(RssPkt,FALSE);
			HANDLERS(LocalQp).FlowGenerator.BuildSteeringParamsFromPacket(SteeringParams,ReWritedPacket);
			HashResult = HANDLERS(LocalQp).FlowGenerator.CalcRssHash(RssDataBase,SteeringParams);
		};

		if (ilog2(RssDataBase.QpGvmiRssNumList.size()) > 0) {
			HashResult = HashResult[ilog2(RssDataBase.QpGvmiRssNumList.size())-1:0];
		} else {
			HashResult = 0;
		};
		result = RssDataBase.QpGvmiRssNumList[HashResult%RssDataBase.QpGvmiRssNumList.size()].GvmiNum;
		return result;
	};

	GetQp(Pkt : NetworkPacket):uint is also {
		if RssMode == RssGroup {
			return GetRssQp(Pkt);
		};
		if IsRoce {
			var Packet : NetworkPacket = Pkt;
			if Packet.InnerPacket != NULL and Packet.InnerPacket.PktType in [RoCE,RRoCE_IP,RRoCE_UDP] {
				Packet = Packet.InnerPacket;
			};
			if Packet.HasHeader(IBTransport) and Packet.IBTransportHeader().TS == DC and Packet.IBTransportHeader().DCETH != NULL and Packet.IBTransportHeader().DCETH.Version == 1 {
				if Packet.IBTransportHeader().OpCodeVal not in [Ack, RDMA_Rd_res_First, RDMA_Rd_res_Mid, RDMA_Rd_res_Last, RDMA_Rd_res_Only, Atom_Ack] {
					return Packet.IBTransportHeader().DCETH.TargetDct;
				} else {
					return Packet.IBTransportHeader().DestQP;
				};
			};
			if Packet.HasHeader(IBTransport){
				return Packet.GetFirstHeader(IBTransport).as_a(IBTransportHeaders).DestQP;
			};
		};
		return QpAllocation.ContextId;
	};
	GetRssQp(Pkt:NetworkPacket) : uint is {
		case RssMode {
			RssGroup : {
				var RssPkt : NetworkPacket = Pkt;
				if Pkt.TunnelType in [EthoIB,IPoIB] and Pkt.InnerPacket != NULL {
					RssPkt = Pkt.InnerPacket;
				};
				var SteeringParams : SteeringParams = new;
				var RssDataBase : RssDataBase = HANDLERS(LocalQp).FlowGenerator.RssDataBaseList.first(it.RssIndex == RssIndex);
				var HashResult : uint;
				if (RssDataBase.RssSubType == ToplitzInner or (RssDataBase.RssSubType == ToplitzByDecap and SteeringNodeInDecapsulationEnabledFlow(TRUE))) and RssPkt.InnerPacket == NULL{
					DUTError(2541,appendf("RssGroup with index %s has RssSubType = %s in DecapsulatedPacket = %s but inner packet is null",RssIndex,RssDataBase.RssSubType,SteeringNodeInDecapsulationEnabledFlow(TRUE)));
				};
				if (RssDataBase.RssSubType == ToplitzInner or (RssDataBase.RssSubType == ToplitzByDecap and SteeringNodeInDecapsulationEnabledFlow(TRUE))) {
					var ReWritedPacket : NetworkPacket = ReWritePacketByNode(RssPkt.InnerPacket,TRUE);
					HANDLERS(LocalQp).FlowGenerator.BuildSteeringParamsFromPacket(SteeringParams,ReWritedPacket);
					HashResult = HANDLERS(LocalQp).FlowGenerator.CalcRssHash(RssDataBase,SteeringParams);
				}else{
					var ReWritedPacket : NetworkPacket = ReWritePacketByNode(RssPkt,FALSE);
					HANDLERS(LocalQp).FlowGenerator.BuildSteeringParamsFromPacket(SteeringParams,ReWritedPacket);
					HashResult = HANDLERS(LocalQp).FlowGenerator.CalcRssHash(RssDataBase,SteeringParams);
				};

				if (ilog2(RssDataBase.QpGvmiRssNumList.size()) > 0) {
					HashResult = HashResult[ilog2(RssDataBase.QpGvmiRssNumList.size())-1:0];
				} else {
					HashResult = 0;
				};

				result = 0;
				if (RssDataBase.QpnSize != 0) {
					result[23:(32/(1 << RssDataBase.QpnSize))-HANDLERS(Config).CrSpaceConfig.Log2NumberOfEntriesInGvmiList] = RssDataBase.BaseQpn[23:(32/(1 << RssDataBase.QpnSize))-HANDLERS(Config).CrSpaceConfig.Log2NumberOfEntriesInGvmiList];
				};
				if (RssDataBase.QpnSize != 0) {
					result[((3-RssDataBase.QpnSize)*8-1)-HANDLERS(Config).CrSpaceConfig.Log2NumberOfEntriesInGvmiList:0] = RssDataBase.QpGvmiRssNumList[HashResult%RssDataBase.QpGvmiRssNumList.size()].QpNum;
				} else {
					result[((3-RssDataBase.QpnSize)*8-1):0] = RssDataBase.QpGvmiRssNumList[HashResult%RssDataBase.QpGvmiRssNumList.size()].QpNum;
				};
				return result;
			};

			StoreHash : {
				DUTError(44252,"StoreHashNode") {
					PrintMe();
				};
			};

			default: {
			};
		};
	};
	GetAllowedNextNodeType() : list of SteeringType  is {
		var KindToCheck : SteeringType = Kind in [STEERING_REGISTER_TYPES] ? ParentNodes.last(TRUE).Kind : Kind;
		if (!Children.is_empty()) {//all sons have the same kind
			result = {Children[0].Kind};
			return result;
		} else if RssMode == RssGroup {
			result = {EndOfTree};
			return result;
		} else if HairPinMode in [BridgeHairPin] {
			result = {EndOfTree};
			return result;
		} else {
			result = {EndOfTree};
			case KindToCheck {
				[MAC_STEERING_TYPE_WITH_DUMMY] : {
					if MulticastNode and KindToCheck == Mac {
						result.delete(result.first_index(it == EndOfTree));
						result.add({MacDummy_0});
					} else if MulticastNode and KindToCheck != Mac {
						result.delete(result.first_index(it == EndOfTree));
						result.add({Ipv6Dst});
					} else {
						result.add({Vlan;Mpls;Ipv6Dst;Ipv6Src;Ipv4_5Tuple;Ipv6L4;Ipv4Dst;Ipv4Src;L4Only;TunnelType});
					};
				};
				[VLAN_STEERING_TYPE_WITH_DUMMY] : {
					result.add({Mpls;Ipv6Dst;Ipv6Src;Ipv4_5Tuple;Ipv6L4;Ipv4Dst;Ipv4Src;L4Only;TunnelType});
				};
				[MPLS_STEERING_TYPE_WITH_DUMMY] : {
					result.add({Ipv6Dst;Ipv6Src;Ipv4_5Tuple;Ipv6L4;Ipv4Dst;Ipv4Src;L4Only;TunnelType});
				};
				[IPV6DST_STEERING_TYPE_WITH_DUMMY] : {
					if not MulticastNode {
						result.add({TunnelType});
						if not {Kind;ParentNodes.Kind}.has(it == Ipv6Src) {
							result.add({Ipv6Src});
						};
						if not {Kind;ParentNodes.Kind}.has(it == Ipv6L4) {
							result.add({Ipv6L4});
						};
					};
				};
				[IPV6SRC_STEERING_TYPE_WITH_DUMMY] : {
					result.add({TunnelType});
					if not {Kind;ParentNodes.Kind}.has(it == Ipv6Dst) {
						result.add({Ipv6Dst});
					};
					if not {Kind;ParentNodes.Kind}.has(it == Ipv6L4) {
						result.add({Ipv6L4});
					};
				};
				[IPV6L4_STEERING_TYPE_WITH_DUMMY] : {
					result.add({TunnelType});
					if not {Kind;ParentNodes.Kind}.has(it == Ipv6Src) {
						result.add({Ipv6Src});
					};
					if not {Kind;ParentNodes.Kind}.has(it == Ipv6Dst) {
						result.add({Ipv6Dst});
					};
				};
				[IPV45TUPLE_STEERING_TYPE_WITH_DUMMY] : {
					result.add({TunnelType});
				};
				[IPV4DST_STEERING_TYPE_WITH_DUMMY] : {
					result.add({TunnelType});
					if not {Kind;ParentNodes.Kind}.has(it == Ipv4Src) {
						result.add({Ipv4Src});
					};
					if not {Kind;ParentNodes.Kind}.has(it == L4Only) {
						result.add({L4Only});
					};
				};
				[IPV4SRC_STEERING_TYPE_WITH_DUMMY] : {
					result.add({TunnelType});
					if not {Kind;ParentNodes.Kind}.has(it == Ipv4Dst) {
						result.add({Ipv4Dst});
					};
					if not {Kind;ParentNodes.Kind}.has(it == L4Only) {
						result.add({L4Only});
					};
				};
				[L4ONLY_STEERING_TYPE_WITH_DUMMY] : {
					result.add({TunnelType});
					if not {Kind;ParentNodes.Kind}.has(it == Ipv4Src) {
						result.add({Ipv4Src});
					};
					if not {Kind;ParentNodes.Kind}.has(it == Ipv4Dst) {
						result.add({Ipv4Dst});
					};
				};
				[ESP_STEERING_TYPE_WITH_DUMMY] : {
					result.add({TunnelType});
					if {Kind;ParentNodes.Kind}.has(it in [Ipv6Dst,Ipv6Src]) {
						if not {Kind;ParentNodes.Kind}.has(it in [Ipv6L4]) {
							result.add({Ipv6L4});
						};
					};
					if {Kind;ParentNodes.Kind}.has(it in [Ipv4Dst,Ipv4Src]) {
						if not {Kind;ParentNodes.Kind}.has(it in [L4Only]) {
							result.add({L4Only});
						};
					};
				};
				TunnelType : {
					if not SteeringNodeInDecapsulationEnabledFlow(TRUE) {
						result.add({InnerIpv6Dst;InnerIpv6Src;InnerIpv4_5Tuple;InnerIpv4Dst;InnerIpv4Src;InnerIpv6L4;InnerL4Only});
						if SteeringTunnelType == VXLAN {
							result.add({InnerMac});
						};
					} else {
						if SteeringNodeInL2DecapsulationEnabledFlow(TRUE) {
							result.add({MacByDecap});
						} else { // L3Decapsulation
							if RxSteeringModificationActions.has(it.InsertAfterL3DecapType == IPv4) {
								result.add({Ipv4_5TupleByDecap;Ipv4DstByDecap;Ipv4SrcByDecap;});
							} else {
								result.add({Ipv6DstByDecap;Ipv6SrcByDecap});
							};
						};
					};
				};
				[INNER_MAC_STEERING_TYPE_WITH_DUMMY] : {
					result.add({InnerVlan;InnerMpls;InnerIpv6Dst;InnerIpv6Src;InnerIpv4_5Tuple;InnerIpv4Dst;InnerIpv4Src;InnerIpv6L4;InnerL4Only});
				};
				[INNER_VLAN_STEERING_TYPE_WITH_DUMMY] : {
					result.add({InnerMpls;InnerIpv6Dst;InnerIpv6Src;InnerIpv4_5Tuple;InnerIpv4Dst;InnerIpv4Src;InnerIpv6L4;InnerL4Only});
				};
				[INNER_MPLS_STEERING_TYPE_WITH_DUMMY] : {
					result.add({InnerIpv6Dst;InnerIpv6Src;InnerIpv4_5Tuple;InnerIpv4Dst;InnerIpv4Src;InnerIpv6L4;InnerL4Only});
				};
				[INNER_IPV6DST_STEERING_TYPE_WITH_DUMMY] : {
					if not {Kind;ParentNodes.Kind}.has(it == InnerIpv6Src) {
						result.add({InnerIpv6Src});
					};
					if not {Kind;ParentNodes.Kind}.has(it == InnerIpv6L4) {
						result.add({InnerIpv6L4});
					};
				};
				[INNER_IPV6SRC_STEERING_TYPE_WITH_DUMMY] : {
					if not {Kind;ParentNodes.Kind}.has(it == InnerIpv6Dst) {
						result.add({InnerIpv6Dst});
					};
					if not {Kind;ParentNodes.Kind}.has(it == InnerIpv6L4) {
						result.add({InnerIpv6L4});
					};
				};
				[INNER_IPV6L4_STEERING_TYPE_WITH_DUMMY] : {
					if not {Kind;ParentNodes.Kind}.has(it == InnerIpv6Dst) {
						result.add({InnerIpv6Dst});
					};
					if not {Kind;ParentNodes.Kind}.has(it == InnerIpv6Src) {
						result.add({InnerIpv6Src});
					};
				};
				[INNER_IPV45TUPLE_STEERING_TYPE_WITH_DUMMY] : {
				};
				[INNER_IPV4DST_STEERING_TYPE_WITH_DUMMY] : {
					if not {Kind;ParentNodes.Kind}.has(it == InnerIpv4Src) {
						result.add({InnerIpv4Src});
					};
					if not {Kind;ParentNodes.Kind}.has(it == InnerL4Only) {
						result.add({InnerL4Only});
					};
				};
				[INNER_IPV4SRC_STEERING_TYPE_WITH_DUMMY] : {
					if not {Kind;ParentNodes.Kind}.has(it == InnerIpv4Dst) {
						result.add({InnerIpv4Dst});
					};
					if not {Kind;ParentNodes.Kind}.has(it == InnerL4Only) {
						result.add({InnerL4Only});
					};
				};
				[INNER_L4ONLY_STEERING_TYPE_WITH_DUMMY] : {
					if not {Kind;ParentNodes.Kind}.has(it == InnerIpv4Src) {
						result.add({InnerIpv4Src});
					};
					if not {Kind;ParentNodes.Kind}.has(it == InnerIpv4Dst) {
						result.add({InnerIpv4Dst});
					};
				};
				[INNER_ESP_STEERING_TYPE_WITH_DUMMY] : {
					if {Kind;ParentNodes.Kind}.has(it in [InnerIpv6Dst,InnerIpv6Src]) {
						if not {Kind;ParentNodes.Kind}.has(it in [InnerIpv6L4]) {
							result.add({InnerIpv6L4});
						};
					};
					if {Kind;ParentNodes.Kind}.has(it in [InnerIpv4Dst,InnerIpv4Src]) {
						if not {Kind;ParentNodes.Kind}.has(it in [InnerL4Only]) {
							result.add({InnerL4Only});
						};
					};
				};
				[MAC_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
					result.add({VlanByDecap;MplsByDecap;Ipv6DstByDecap;Ipv6SrcByDecap;Ipv4_5TupleByDecap;Ipv4DstByDecap;Ipv4SrcByDecap;Ipv6L4ByDecap;L4OnlyByDecap});
				};
				[VLAN_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
					result.add({MplsByDecap;Ipv6DstByDecap;Ipv6SrcByDecap;Ipv4_5TupleByDecap;Ipv4DstByDecap;Ipv4SrcByDecap;Ipv6L4ByDecap;L4OnlyByDecap});
				};
				[MPLS_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
					result.add({Ipv6DstByDecap;Ipv6SrcByDecap;Ipv4_5TupleByDecap;Ipv4DstByDecap;Ipv4SrcByDecap;Ipv6L4ByDecap;L4OnlyByDecap});
				};
				[IPV6DST_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
					if not {Kind;ParentNodes.Kind}.has(it == Ipv6SrcByDecap) {
						result.add({Ipv6SrcByDecap});
					};
					if not {Kind;ParentNodes.Kind}.has(it == Ipv6L4ByDecap) {
						result.add({Ipv6L4ByDecap});
					};
				};
				[IPV6SRC_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
					if not {Kind;ParentNodes.Kind}.has(it == Ipv6DstByDecap) {
						result.add({Ipv6DstByDecap});
					};
					if not {Kind;ParentNodes.Kind}.has(it == Ipv6L4ByDecap) {
						result.add({Ipv6L4ByDecap});
					};
				};
				[IPV6L4_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
					if not {Kind;ParentNodes.Kind}.has(it == Ipv6DstByDecap) {
						result.add({Ipv6DstByDecap});
					};
					if not {Kind;ParentNodes.Kind}.has(it == Ipv6SrcByDecap) {
						result.add({Ipv6SrcByDecap});
					};
				};
				[IPV45TUPLE_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
				};
				[IPV4DST_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
					if not {Kind;ParentNodes.Kind}.has(it == Ipv4SrcByDecap) {
						result.add({Ipv4SrcByDecap});
					};
					if not {Kind;ParentNodes.Kind}.has(it == L4OnlyByDecap) {
						result.add({L4OnlyByDecap});
					};
				};
				[IPV4SRC_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
					if not {Kind;ParentNodes.Kind}.has(it == Ipv4DstByDecap) {
						result.add({Ipv4DstByDecap});
					};
					if not {Kind;ParentNodes.Kind}.has(it == L4OnlyByDecap) {
						result.add({L4OnlyByDecap});
					};
				};
				[L4ONLY_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
					if not {Kind;ParentNodes.Kind}.has(it == Ipv4SrcByDecap) {
						result.add({Ipv4SrcByDecap});
					};
					if not {Kind;ParentNodes.Kind}.has(it == Ipv4DstByDecap) {
						result.add({Ipv4DstByDecap});
					};
				};
				[ESP_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
					if {Kind;ParentNodes.Kind}.has(it in [Ipv6DstByDecap,Ipv6SrcByDecap]) {
						if not {Kind;ParentNodes.Kind}.has(it in [Ipv6L4ByDecap]) {
							result.add({Ipv6L4ByDecap});
						};
					};
					if {Kind;ParentNodes.Kind}.has(it in [Ipv4DstByDecap,Ipv4SrcByDecap]) {
						if not {Kind;ParentNodes.Kind}.has(it in [L4OnlyByDecap]) {
							result.add({L4OnlyByDecap});
						};
					};
				};
				Lid : {
					if HANDLERS(LocalQp).FlowGenerator.GvmiResolutionMode == GID {
						result = {Gid};
						return result;
					};
					if IBSteeringMode in [IpoIbOnly] and IpoIBType == IPv4Dst {
						result.add({Ipv4Dst});
					};
					if IBSteeringMode in [IpoIbOnly] and IpoIBType == IPv4Src {
						result.add({Ipv4Src});
					};
					if IBSteeringMode in [IpoIbOnly] and IpoIBType == IPv45Tuple {
						result.add({Ipv4_5Tuple});
					};
					if IBSteeringMode in [IpoIbOnly] and IpoIBType == IPv6Dst {
						result.add({Ipv6Dst});
					};
					if IBSteeringMode in [IpoIbOnly] and IpoIBType == IPv6Src {
						result.add({Ipv6Src});
					};
				};
				Gid : {
					if IBSteeringMode in [IpoIbOnly] and IpoIBType == IPv4Dst {
						result.add({Ipv4Dst});
					};
					if IBSteeringMode in [IpoIbOnly] and IpoIBType == IPv4Src {
						result.add({Ipv4Src});
					};
					if IBSteeringMode in [IpoIbOnly] and IpoIBType == IPv45Tuple {
						result.add({Ipv4_5Tuple});
					};
					if IBSteeringMode in [IpoIbOnly] and IpoIBType == IPv6Dst {
						result.add({Ipv6Dst});
					};
					if IBSteeringMode in [IpoIbOnly] and IpoIBType == IPv6Src {
						result.add({Ipv6Src});
					};
				};
			};
			if RemoteFlow { // in RemoteFlow - PRIO is defined by source QP and it's complicated to match it; no need for those flows will all the cases are covered in different places
				if result.has(it == Vlan) {
					result.delete(result.first_index(it == Vlan));
				};
				if result.has(it == Mpls) {
					result.delete(result.first_index(it == Mpls));
				};
			};
			if IsRoce {
				result = result.all(it in [EndOfTree,MAC_STEERING_TYPE_WITH_DUMMY,VLAN_STEERING_TYPE_WITH_DUMMY,MPLS_STEERING_TYPE_WITH_DUMMY,IPV6DST_STEERING_TYPE_WITH_DUMMY,IPV4DST_STEERING_TYPE_WITH_DUMMY,ESP_STEERING_TYPE_WITH_DUMMY, STEERING_REGISTER_TYPES]);
				if GetMaxSxTagDataSize() == 0 {
					if result.has(it in [VLAN_STEERING_TYPE_WITH_DUMMY]) {
						for each (VlanType) in result.all(it in [VLAN_STEERING_TYPE_WITH_DUMMY]) {
							result.delete(result.first_index(it == VlanType));
						};
					};
				};
			};

			if SteeringNodeInEncapsulationEnabledFlow(TRUE) {
				var EncapSteeringNode : SteeringNode = SteeringNodeHasEncapAction() ? me : {me;ParentNodes}.last(it.SteeringNodeHasEncapAction());
				var AllowedTypesByEncapPkt : list of SteeringType = HANDLERS(LocalQp).FlowGenerator.GetAllowedNodeTypesFromEncapsulatedPacket(EncapSteeringNode);
				result = result.all(it in AllowedTypesByEncapPkt);
				if result.is_empty() {
					result = AddDummySteeringTypesAccordingToKind(Kind);
				};
			};

			if HANDLERS(LocalQp).FlowGenerator.PatchToCloseTunnelTypeInIPSecUnawareFlow {
				if RxIPSecHostType == Unaware or SxIPSecHostType == Unaware {
					if result.has(it == TunnelType) {
						result.delete(result.first_index(it == TunnelType));
					};
					if result.has(it == Ipv6L4) {
						result.delete(result.first_index(it == Ipv6L4));
					};
					if result.has(it == L4Only) {
						result.delete(result.first_index(it == L4Only));
					};
					if ParentNodes.has(it.Kind == Ipv6Dst and (it.RxIPSecHostType == Unaware or it.SxIPSecHostType == Unaware)) and result.has(it == Ipv6Src) {
						result.delete(result.first_index(it == Ipv6Src));
					};
					if ParentNodes.has(it.Kind == Ipv4Dst and (it.RxIPSecHostType == Unaware or it.SxIPSecHostType == Unaware)) and result.has(it == Ipv4Src) {
						result.delete(result.first_index(it == Ipv4Src));
					};
					if ParentNodes.has(it.Kind == Ipv6Src and (it.RxIPSecHostType == Unaware or it.SxIPSecHostType == Unaware)) and result.has(it == Ipv6Dst) {
						result.delete(result.first_index(it == Ipv6Dst));
					};
					if ParentNodes.has(it.Kind == Ipv4Src and (it.RxIPSecHostType == Unaware or it.SxIPSecHostType == Unaware)) and result.has(it == Ipv4Dst) {
						result.delete(result.first_index(it == Ipv4Dst));
					};
				};
			};
			if SteeringNodeHasAsoActions(BOTH,{ASO_IPSec}) {
				if SteeringNodeHasAsoActions(RX) {
					result.clear();
					result.add(GetRelevantRegisterSteeringType(RX));
				} else {
					result.clear();
					result.add(GetRelevantRegisterSteeringType(SX));
				};
			};
			if RxIPSecHostType == Unaware {
				if RxActionRequired == IpsecUnawareRx_Stage0 {
					result.clear();
					result = AddDummySteeringTypesAccordingToKind(KindToCheck); //Dummy_0 expected
				};
				if RxActionRequired == IpsecUnawareRx_Stage1 {
					if SteeringNodeHasAsoActions(RX) {
						result.clear();
						result.add(GetRelevantRegisterSteeringType(RX));
					} else {
						result.clear();
						result.add(GetRelevantRegisterSteeringType(SX));
					};
				};
				if RxActionRequired == IpsecUnawareRx_Stage2 {
					result.clear();
					var KindForDummy : SteeringType = {me;ParentNodes}.first(it.RxActionRequired == IpsecUnawareRx_Stage1).Kind;
					result = AddDummySteeringTypesAccordingToKind(KindForDummy); //Dummy_1 expected
				};
				if RxActionRequired == IpsecUnawareRx_Stage3 {
					result.clear();
					result = AddDummySteeringTypesAccordingToKind(KindToCheck); //Dummy_2 expected
				};
			};
			if RxIPSecHostType == Aware or SxIPSecHostType == Aware {
				if RxActionRequired == IpsecAwareRx or SxActionRequired == IpsecAwareSx {
					if KindToCheck in [Ipv6Dst,Ipv6Src,Ipv4Dst,Ipv4Src] {
						result.clear();
						result.add({Esp});
					} else if KindToCheck in [Ipv6DstByDecap,Ipv6SrcByDecap,Ipv4DstByDecap,Ipv4SrcByDecap] {
						result.clear();
						result.add({EspByDecap});
					} else if KindToCheck in [InnerIpv6Dst,InnerIpv6Src,InnerIpv4Dst,InnerIpv4Src] {
						result.clear();
						result.add({InnerEsp});
					};
				};
				if result.has(it in [TunnelType,ALL_IPV45TUPLE_STEERING_TYPE_WITH_DUMMY,ALL_L4ONLY_STEERING_TYPE_WITH_DUMMY,ALL_IPV6L4_STEERING_TYPE_WITH_DUMMY]) {
					var L4Kinds : list of SteeringType = ENUMS_TO_LIST(TunnelType,ALL_IPV45TUPLE_STEERING_TYPE_WITH_DUMMY,ALL_L4ONLY_STEERING_TYPE_WITH_DUMMY,ALL_IPV6L4_STEERING_TYPE_WITH_DUMMY);
					for each (L4Kind) in L4Kinds {
						if result.has(it == L4Kind) {
							result.delete(result.first_index(it == L4Kind));
						};
					};
				};
			};
            if RxMACSecHostType == Unaware {
                if RxActionRequired == MacsecUnawareRx_Stage0 {
                    result.clear();
                    result = AddDummySteeringTypesAccordingToKind(KindToCheck); //Dummy_0 expected
                };
                if RxActionRequired == MacsecUnawareRx_Stage1 {
                    if SteeringNodeHasAsoActions(RX) {
                        result.clear();
                        result.add(GetRelevantRegisterSteeringType(RX));
                    } else {
                        result.clear();
                        result.add(GetRelevantRegisterSteeringType(SX));
                    };
                };
                if RxActionRequired == MacsecUnawareRx_Stage2 {
                    result.clear();
                    var KindForDummy : SteeringType = {me;ParentNodes}.first(it.RxActionRequired == MacsecUnawareRx_Stage1).Kind;
                    result = AddDummySteeringTypesAccordingToKind(KindForDummy); //Dummy_1 expected
                };
                if RxActionRequired == MacsecUnawareRx_Stage3 {
                    result.clear();
                    result = AddDummySteeringTypesAccordingToKind(KindToCheck); //Dummy_2 expected
                };
                if RxActionRequired == MacsecUnawareRx_Stage4 {
                    result.clear();
                    result = AddDummySteeringTypesAccordingToKind(KindToCheck);
                };
                if RxActionRequired not in [MACSEC_ACTION_REQUIRED_TYPES] {
                    result.clear();
                    result.add(EndOfTree);
                };
                
            };
			if result.has(it == EndOfTree) and CanNotBeEndOfTree() {
				result.delete(result.first_index(it == EndOfTree));
			};
			if HasL4TypeTcpInOuter() {
				if result.has(it == TunnelType) {
					result.delete(result.first_index(it == TunnelType));
				};
			};
			if result.is_empty() {
				if KindToCheck in [Esp,EspByDecap,InnerEsp] {
					var KindForDummy : SteeringType = {me;ParentNodes}.first(it.SteeringNodeHasIpsecActions(RX) or it.SteeringNodeHasIpsecActions(SX)).Kind;
					KindForDummy = appendf("%sDummy_0",KindForDummy).as_a(SteeringType);
					result = AddDummySteeringTypesAccordingToKind(KindForDummy);
				} else {
					result = AddDummySteeringTypesAccordingToKind(KindToCheck);
				};
			};
			if RssMode == StoreHash {
				result.delete(result.first_index(it == EndOfTree));
			};
		};
	};

	GetRelevantRegisterSteeringType(RxSxFlow : RxSxType) : SteeringType is {
		var RegisterID : uint;
		if RxSxFlow == RX {
			RegisterID = RxSteeringInlineActions.first(it.RxInlineActionType in [ASO_INLINE_ACTION_TYPE]).AsoDestinationRegisterID;
		} else {
			RegisterID = SxSteeringInlineActions.first(it.SxInlineActionType in [ASO_INLINE_ACTION_TYPE]).AsoDestinationRegisterID;
		};
		case RegisterID {
			0x0 : {
				return Register0;
			};
			0x1 : {
				return Register1;
			};
			0x2 : {
				return Register2;
			};
			0x3 : {
				return Register3;
			};
			0x4 : {
				return Register4;
			};
			0x5 : {
				return Register5;
			};
		};
	};

	CanNotBeEndOfTree() : bool is {
		//9. IPSec/Queue_ID are never terminator steering entries
		if SteeringNodeHasVOQActions() or SteeringNodeHasIpsecActions(BOTH) {
			return TRUE;
		};
		//17. no modifications (inline or list) on last steering entry / steering entry with terminator action
		if WithRxModificationActions or WithSxModificationActions {
			return TRUE;
		};
		//23. ASO does not work with terminators
		if SteeringNodeHasAsoActions(BOTH) {
			return TRUE;
		};
		if Kind in [Lid,Gid] and IBSteeringMode in [IpoIbOnly] {
			return TRUE;
		};
		result = FALSE;
	};

	HasL4TypeTcpInOuter() : bool is {
		result = FALSE;
		if {me;ParentNodes}.has(it.Kind in [L4Only,Ipv6L4,Ipv4_5Tuple] and it.L4Type == TCP) {
			return TRUE;
		};
	};

	AddDummySteeringTypesAccordingToKind(KindForDummy : SteeringType) : list of SteeringType is {
		case KindForDummy {
			[   Mac,                Vlan,               Mpls,               Ipv6Dst,                Ipv6Src,                Ipv4_5Tuple,                Ipv4Dst,                Ipv4Src,                Ipv6L4,                 L4Only,                 Esp,
				MacByDecap,         VlanByDecap,        MplsByDecap,        Ipv6DstByDecap,         Ipv6SrcByDecap,         Ipv4_5TupleByDecap,         Ipv4DstByDecap,         Ipv4SrcByDecap,         Ipv6L4ByDecap,          L4OnlyByDecap,          EspByDecap,
				InnerMac,           InnerVlan,          InnerMpls,          InnerIpv6Dst,           InnerIpv6Src,           InnerIpv4_5Tuple,           InnerIpv4Dst,           InnerIpv4Src,           InnerIpv6L4,            InnerL4Only,            InnerEsp] :
			{
				result = {appendf("%sDummy_0",KindForDummy).as_a(SteeringType)};
			};
			[   MacDummy_0,         VlanDummy_0,        MplsDummy_0,        Ipv6DstDummy_0,         Ipv6SrcDummy_0,         Ipv4_5TupleDummy_0,         Ipv4DstDummy_0,         Ipv4SrcDummy_0,         Ipv6L4Dummy_0,          L4OnlyDummy_0,          EspDummy_0,
				MacByDecapDummy_0,  VlanByDecapDummy_0, MplsByDecapDummy_0, Ipv6DstByDecapDummy_0,  Ipv6SrcByDecapDummy_0,  Ipv4_5TupleByDecapDummy_0,  Ipv4DstByDecapDummy_0,  Ipv4SrcByDecapDummy_0,  Ipv6L4ByDecapDummy_0,   L4OnlyByDecapDummy_0,   EspByDecapDummy_0,
				InnerMacDummy_0,    InnerVlanDummy_0,   InnerMplsDummy_0,   InnerIpv6DstDummy_0,    InnerIpv6SrcDummy_0,    InnerIpv4_5TupleDummy_0,    InnerIpv4DstDummy_0,    InnerIpv4SrcDummy_0,    InnerIpv6L4Dummy_0,     InnerL4OnlyDummy_0,     InnerEspDummy_0
			] :
			{
				var DummyKindWithoutIndex : string = str_sub(KindForDummy.as_a(string), 0, str_len(KindForDummy.as_a(string)) - 1);
				result = {appendf("%s1",DummyKindWithoutIndex).as_a(SteeringType)};
			};
			[   MacDummy_1,         VlanDummy_1,        MplsDummy_1,        Ipv6DstDummy_1,         Ipv6SrcDummy_1,         Ipv4_5TupleDummy_1,         Ipv4DstDummy_1,         Ipv4SrcDummy_1,         Ipv6L4Dummy_1,          L4OnlyDummy_1,          EspDummy_1,
				MacByDecapDummy_1,  VlanByDecapDummy_1, MplsByDecapDummy_1, Ipv6DstByDecapDummy_1,  Ipv6SrcByDecapDummy_1,  Ipv4_5TupleByDecapDummy_1,  Ipv4DstByDecapDummy_1,  Ipv4SrcByDecapDummy_1,  Ipv6L4ByDecapDummy_1,   L4OnlyByDecapDummy_1,   EspByDecapDummy_1,
				InnerMacDummy_1,    InnerVlanDummy_1,   InnerMplsDummy_1,   InnerIpv6DstDummy_1,    InnerIpv6SrcDummy_1,    InnerIpv4_5TupleDummy_1,    InnerIpv4DstDummy_1,    InnerIpv4SrcDummy_1,    InnerIpv6L4Dummy_1,     InnerL4OnlyDummy_1,     InnerEspDummy_1
			] :
			{
				var DummyKindWithoutIndex : string = str_sub(KindForDummy.as_a(string), 0, str_len(KindForDummy.as_a(string)) - 1);
				result = {appendf("%s2",DummyKindWithoutIndex).as_a(SteeringType)};
			};
			[   MacDummy_2,         VlanDummy_2,        MplsDummy_2,        Ipv6DstDummy_2,         Ipv6SrcDummy_2,         Ipv4_5TupleDummy_2,         Ipv4DstDummy_2,         Ipv4SrcDummy_2,         Ipv6L4Dummy_2,          L4OnlyDummy_2,          EspDummy_2,
				MacByDecapDummy_2,  VlanByDecapDummy_2, MplsByDecapDummy_2, Ipv6DstByDecapDummy_2,  Ipv6SrcByDecapDummy_2,  Ipv4_5TupleByDecapDummy_2,  Ipv4DstByDecapDummy_2,  Ipv4SrcByDecapDummy_2,  Ipv6L4ByDecapDummy_2,   L4OnlyByDecapDummy_2,   EspByDecapDummy_2,
				InnerMacDummy_2,    InnerVlanDummy_2,   InnerMplsDummy_2,   InnerIpv6DstDummy_2,    InnerIpv6SrcDummy_2,    InnerIpv4_5TupleDummy_2,    InnerIpv4DstDummy_2,    InnerIpv4SrcDummy_2,    InnerIpv6L4Dummy_2,     InnerL4OnlyDummy_2,     InnerEspDummy_2
			] :
			{
				var DummyKindWithoutIndex : string = str_sub(KindForDummy.as_a(string), 0, str_len(KindForDummy.as_a(string)) - 1);
				result = {appendf("%s3",DummyKindWithoutIndex).as_a(SteeringType)};
			};
		};
		return result;
	};


	GetEncapsulationPacketLookupTypes() : list of SteeringType is {
		if EncapsulationDataBase.Packet.HasHeader(IPv4) {
			result.add(Ipv4_5Tuple);
		};
		if EncapsulationDataBase.Packet.HasHeader(IPv6) {
			result.add({Ipv6Dst;Ipv6Src});
			if (EncapsulationDataBase.Packet.HasHeader(TCP) or EncapsulationDataBase.Packet.HasHeader(UDP)) {
				result.add(Ipv6L4);
			};
		};
	};

	GetPortPrio2Mpls(Prio: uint = UNDEF) : list of uint(bits:3) is {
		if Prio == UNDEF {
			Prio = HANDLERS(Config).GetPortConfigInfo(SteeringTree.Port).PrioInfo.DefaultPrio;
		};
		var ConfigRequirements = new with {
			.PortNum = SteeringTree.Port;
		};
		result = HANDLERS(Config).Prio2Mpls(ConfigRequirements, Prio);
	};

	SteeringNodeHasPopVlanActions(RxSxFlow : RxSxType) : bool is also {
		if RxSxFlow == BOTH {
			if RxSteeringModificationActions.RxModificationActionType.has(it in [PopVlan]) or SxSteeringModificationActions.SxModificationActionType.has(it in [PopVlan]) {
				return TRUE;
			};
		} else if RxSxFlow == RX {
			if RxSteeringModificationActions.RxModificationActionType.has(it in [PopVlan]) {
				return TRUE;
			};
		} else if RxSxFlow == SX {
			if SxSteeringModificationActions.SxModificationActionType.has(it in [PopVlan]) {
				return TRUE;
			};
		};
	};

	SteeringNodeHasRewriteActions(RxSxFlow : RxSxType) : bool is also {
		if RxSxFlow == BOTH {
			if RxSteeringModificationActions.RxModificationActionType.has(it in [Add,Set,Copy]) or SxSteeringModificationActions.SxModificationActionType.has(it in [Add,Set,Copy]) {
				return TRUE;
			};
		} else if RxSxFlow == RX {
			if RxSteeringModificationActions.RxModificationActionType.has(it in [Add,Set,Copy]) {
				return TRUE;
			};
		} else if RxSxFlow == SX {
			if SxSteeringModificationActions.SxModificationActionType.has(it in [Add,Set,Copy]) {
				return TRUE;
			};
		};
	};

	SteeringNodeHasVOQActions() : bool is {
		if RxSteeringInlineActions.RxInlineActionType.has(it in [QueueIDSelection]) {
			return TRUE;
		};
	};

	SteeringNodeHasIpsecActions(RxSxFlow : RxSxType) : bool is also {
		if RxSxFlow == RX {
			if RxSteeringInlineActions.RxInlineActionType.has(it in [IpsecAware, IpsecUnaware]) {
				return TRUE;
			};
		} else if RxSxFlow == SX {
			if SxSteeringInlineActions.SxInlineActionType.has(it in [IpsecAware, IpsecUnaware]) {
				return TRUE;
			};
		} else {
			if RxSteeringInlineActions.RxInlineActionType.has(it in [IpsecAware, IpsecUnaware]) or SxSteeringInlineActions.SxInlineActionType.has(it in [IpsecAware, IpsecUnaware]) {
				return TRUE;
			};
		};
	};

	SteeringNodeHasIpsecAwareActions(RxSxFlow : RxSxType) : bool is {
		if RxSxFlow == RX {
			if RxSteeringInlineActions.RxInlineActionType.has(it in [IpsecAware]) {
				return TRUE;
			};
		} else if RxSxFlow == SX {
			if SxSteeringInlineActions.SxInlineActionType.has(it in [IpsecAware]) {
				return TRUE;
			};
		} else {
			if RxSteeringInlineActions.RxInlineActionType.has(it in [IpsecAware]) or SxSteeringInlineActions.SxInlineActionType.has(it in [IpsecAware]) {
				return TRUE;
			};
		};
	};

	SteeringNodeHasIpsecUnawareActions(RxSxFlow : RxSxType) : bool is {
		if RxSxFlow == RX {
			if RxSteeringInlineActions.RxInlineActionType.has(it in [IpsecUnaware]) {
				return TRUE;
			};
		} else if RxSxFlow == SX {
			if SxSteeringInlineActions.SxInlineActionType.has(it in [IpsecUnaware]) {
				return TRUE;
			};
		} else {
			if RxSteeringInlineActions.RxInlineActionType.has(it in [IpsecUnaware]) or SxSteeringInlineActions.SxInlineActionType.has(it in [IpsecUnaware]) {
				return TRUE;
			};
		};
	};

	SteeringNodeHasMacSecActions(RxSxFlow : RxSxType) : bool is also {
		if RxSxFlow == RX {
			if RxSteeringInlineActions.RxInlineActionType.has(it in [MacsecUnaware]) {
				return TRUE;
			};
		} else if RxSxFlow == SX {
			if SxSteeringInlineActions.SxInlineActionType.has(it in [MacsecUnaware]) {
				return TRUE;
			};
		} else {
			if RxSteeringInlineActions.RxInlineActionType.has(it in [MacsecUnaware]) or SxSteeringInlineActions.SxInlineActionType.has(it in [MacsecUnaware]) {
				return TRUE;
			};
		};
	};

	SteeringNodeHasTraActions() : bool is also {
		if RxSteeringInlineActions.RxInlineActionType.has(it in [Tra]) {
			return TRUE;
		};
	};

	SteeringNodeHasAsoCTActions(RxSxFlow : RxSxType) : bool is {
		if RxSxFlow == RX {
			if RxSteeringInlineActions.RxInlineActionType.has(it in [ASO_ConnectionTracking]) {
				return TRUE;
			};
		} else if RxSxFlow == SX {
			if SxSteeringInlineActions.SxInlineActionType.has(it in [ASO_ConnectionTracking]) {
				return TRUE;
			};
		} else {
			if RxSteeringInlineActions.RxInlineActionType.has(it in [ASO_ConnectionTracking]) or SxSteeringInlineActions.SxInlineActionType.has(it in [ASO_ConnectionTracking]) {
				return TRUE;
			};
		};
	};

	SteeringNodeHasAsoRAActions(RxSxFlow : RxSxType) : bool is {
		if RxSxFlow == RX {
			if RxSteeringInlineActions.RxInlineActionType.has(it in [ASO_RaceAvoidance]) {
				return TRUE;
			};
		} else if RxSxFlow == SX {
			if SxSteeringInlineActions.SxInlineActionType.has(it in [ASO_RaceAvoidance]) {
				return TRUE;
			};
		} else {
			if RxSteeringInlineActions.RxInlineActionType.has(it in [ASO_RaceAvoidance]) or SxSteeringInlineActions.SxInlineActionType.has(it in [ASO_RaceAvoidance]) {
				return TRUE;
			};
		};
	};

	SteeringNodeHasAsoFHActions(RxSxFlow : RxSxType) : bool is {
		if RxSxFlow == RX {
			if RxSteeringInlineActions.RxInlineActionType.has(it in [ASO_FirstHit]) {
				return TRUE;
			};
		} else if RxSxFlow == SX {
			if SxSteeringInlineActions.SxInlineActionType.has(it in [ASO_FirstHit]) {
				return TRUE;
			};
		} else {
			if RxSteeringInlineActions.RxInlineActionType.has(it in [ASO_FirstHit]) or SxSteeringInlineActions.SxInlineActionType.has(it in [ASO_FirstHit]) {
				return TRUE;
			};
		};
	};

	SteeringNodeHasAsoActions(RxSxFlow : RxSxType, ExcludeList : list of SteeringNodeActionType = {}) : bool is {
		var AsoInlineActionListToCheck : list of SteeringNodeActionType;
		var AsoInlineActionList : list of SteeringNodeActionType = ENUMS_TO_LIST(ASO_INLINE_ACTION_TYPE);
		for each (AsoInlineActionType) in AsoInlineActionList {
			if AsoInlineActionType not in ExcludeList {
				AsoInlineActionListToCheck.add(AsoInlineActionType);
			};
		};
		if RxSxFlow == RX {
			if RxSteeringInlineActions.RxInlineActionType.has(it in AsoInlineActionListToCheck) {
				return TRUE;
			};
		} else if RxSxFlow == SX {
			if SxSteeringInlineActions.SxInlineActionType.has(it in AsoInlineActionListToCheck) {
				return TRUE;
			};
		} else {
			if RxSteeringInlineActions.RxInlineActionType.has(it in AsoInlineActionListToCheck) or SxSteeringInlineActions.SxInlineActionType.has(it in AsoInlineActionListToCheck) {
				return TRUE;
			};
		};
	};

	SteeringNodeHasInsertWithPointer(RxSxFlow : RxSxType) : bool is {
		if RxSxFlow == RX {
			if RxSteeringModificationActions.RxModificationActionType.has(it in [InsertWithPointer]) {
				return TRUE;
			};
		} else if RxSxFlow == SX {
			if SxSteeringModificationActions.SxModificationActionType.has(it in [InsertWithPointer]) {
				return TRUE;
			};
		} else {
			if RxSteeringModificationActions.RxModificationActionType.has(it in [InsertWithPointer]) or SxSteeringModificationActions.SxModificationActionType.has(it in [InsertWithPointer]) {
				return TRUE;
			};
		};
	};
	SteeringNodeHasL2EncapAction() : bool is {
		return SxSteeringModificationActions.SxModificationActionType.has(it in [Encapsulation]);
	};

	SteeringNodeHasL3EncapAction() : bool is {
		return SxSteeringModificationActions.SxModificationActionType.has(it in [L3Encapsulation]);
	};
	SteeringNodeHasEncapAction() : bool is {
		return SteeringNodeHasL3EncapAction() or SteeringNodeHasL2EncapAction();
	};
	SteeringNodeGenerationSanityCheck() is {
		if (not RxSteeringInlineActions.has(it.SteeringNodeInlineActionsSize == None)) {
			DUTError(223300,appendf("This Node can't be EndOfTree need to Fix"));
		} else if (RxSteeringInlineActions.has(it.SteeringNodeInlineActionsSize == None) and RxSteeringInlineActions.has(it.SteeringNodeInlineActionsSize == DoubleDW) and WithRxModificationActions) {
			DUTError(223301,appendf("This Node can't be EndOfTree need to Fix"));
		} else if (RxSteeringInlineActions.has(it.SteeringNodeInlineActionsSize == None) and RxSteeringInlineActions.count(it.SteeringNodeInlineActionsSize == SingleDW) == 2 and WithRxModificationActions) {
			DUTError(223303,appendf("This Node can't be EndOfTree need to Fix"));
		} else if (not SxSteeringInlineActions.has(it.SteeringNodeInlineActionsSize == None)) {
			DUTError(223304,appendf("This Node can't be EndOfTree need to Fix"));
		} else if (SxSteeringInlineActions.has(it.SteeringNodeInlineActionsSize == None) and SxSteeringInlineActions.has(it.SteeringNodeInlineActionsSize == DoubleDW) and WithSxModificationActions) {
			DUTError(223305,appendf("This Node can't be EndOfTree need to Fix"));
		} else if (SxSteeringInlineActions.has(it.SteeringNodeInlineActionsSize == None) and SxSteeringInlineActions.count(it.SteeringNodeInlineActionsSize == SingleDW) == 2 and WithSxModificationActions) {
			DUTError(223306,appendf("This Node can't be EndOfTree need to Fix"));
		} else if SteeringNodeHasAsoCTActions(BOTH) {
			DUTError(223307,appendf("This Node can't be EndOfTree need to Fix"));
		};
	};

	NeedToResetSxTransmitNowEnabledForParents() : bool is {
		if {me;ParentNodes}.has(it.SxIPSecHostType != None) {
			return TRUE;
		};
		if {me;ParentNodes}.has(it.SteeringNodeInEncapsulationEnabledFlow(TRUE)) {
			return TRUE;
		};
	};

	BuildTree(SteeringTree : SteeringTree , TotalNumOfFlowsCounter : uint, GvmiInfo : GvmiInfo, MustReWriteActionType : ActionRequired = None) is {
		gen NumOfChildren;
		if NumOfChildren != 0 {
			var MaxFlowPerChild : list of uint;
			MaxFlowPerChild = GenDistribution(MaxNumOfChildren,NumOfChildren, 1 ,MaxNumOfChildren);
			for i from 0 to NumOfChildren-1{
				gen NextNodeType;
				if NextNodeType == WredMask { // in case of WredMask this Mac must have specific Mask
					NumOfChildren = 1;
					MaxFlowPerChild = GenDistribution(MaxNumOfChildren,NumOfChildren, 1 ,MaxNumOfChildren);
				};
				gen NextValueType;
				if ParentNodes.HairPinMode.has(it != None) {
					HairPinMode = ParentNodes.HairPinMode.first(it != None);
				};
				if NextNodeType == Gid and GvmiInfo.GvmiContexts.key(SteeringTree.Port).GidTable.is_empty() { // TODO - Najeeb: unfortunately in case of IB Port and Gid GvmiResolution there is  GvmiInfo.GvmiContexts.key(SteeringTree.Port) with empty GidTable
					SteeringTree.IBSteeringMode = IbOnly;
					NextNodeType = EndOfTree;
				};
				if NextNodeType == EndOfTree {
					IsEndNode = TRUE;
					gen TunnelingEnable;
					SteeringNodeGenerationSanityCheck();
					continue;
				};
				gen NewChild keeping {
					it.Kind == read_only(NextNodeType);
					it.ValueType == read_only(NextValueType);
					it.MulticastNode == read_only(MulticastNode);
					it.SteeringTree == read_only(SteeringTree);
					it.NodeIndex == read_only(HANDLERS(LocalQp).FlowGenerator.NodeIndex);
					it.MaxNumOfChildren == read_only(MaxFlowPerChild[i]);
					it.ParentNodes == read_only({ParentNodes; me});
					it.IBSteeringMode == read_only(SteeringTree.RootNode.IBSteeringMode);
					it.IpoIBType == read_only(SteeringTree.RootNode.IpoIBType);
					it.Register0InUse == Register0InUse;
					it.Register1InUse == Register1InUse;
					it.Register2InUse == Register2InUse;
					it.Register3InUse == Register3InUse;
					it.Register4InUse == Register4InUse;
					it.Register5InUse == Register5InUse;
					it.RxRegister0Value == RxRegister0Value;
					it.RxRegister1Value == RxRegister1Value;
					it.RxRegister2Value == RxRegister2Value;
					it.RxRegister3Value == RxRegister3Value;
					it.RxRegister4Value == RxRegister4Value;
					it.RxRegister5Value == RxRegister5Value;
					it.SxRegister0Value == SxRegister0Value;
					it.SxRegister1Value == SxRegister1Value;
					it.SxRegister2Value == SxRegister2Value;
					it.SxRegister3Value == SxRegister3Value;
					it.SxRegister4Value == SxRegister4Value;
					it.SxRegister5Value == SxRegister5Value;
				};
				if NewChild.MulticastNode {
					NewChild.MulticastGroup = MulticastGroup;
				};
				if NewChild.Kind in [Ipv6Dst,Ipv6Src,Ipv4Dst,Ipv4Src,Ipv4_5Tuple,InnerIpv6Dst,InnerIpv6Src,InnerIpv4Dst,InnerIpv4Src,InnerIpv4_5Tuple,Ipv6DstByDecap,Ipv6SrcByDecap,Ipv4DstByDecap,Ipv4SrcByDecap,Ipv4_5TupleByDecap] {
					gen NewChild.L3Type;
				} else if NewChild.Kind == TunnelType {
					NewChild.L3Type = None; // reset L3Type for next level (InnerPacket)
				} else {
					NewChild.L3Type = L3Type;
				};
				if NewChild.Kind in [Ipv6L4,Ipv6L4ByDecap,InnerIpv6L4,L4Only,L4OnlyByDecap,InnerL4Only,Ipv4_5Tuple,Ipv4_5TupleByDecap,InnerIpv4_5Tuple] {
					gen NewChild.L4Type;
				} else if NewChild.Kind == TunnelType {
					NewChild.L4Type = None; // reset L4Type for next level (InnerPacket)
				} else {
					NewChild.L4Type = L4Type;
				};
				//gen NewChild.IsRss;
				gen NewChild.RssMode;
				NewChild.LevelInTree = LevelInTree + 1;
				AddChild(LevelInTree+1,NewChild);
				if NewChild.Kind == Gid {
					for each (GidNum) in GvmiInfo.GvmiContexts.key(SteeringTree.Port).GidTable.Gid {
						messagef(HIGH,"Gid: 0x%x, Index = 0x%x",GidNum,index);
					};
					NewChild.BuildGidSteeringNode(GvmiInfo.GvmiContexts.key(SteeringTree.Port).GidTable.Gid);
				} else {
					NewChild.BuildSteeringNode();
				};
				TotalNumOfFlowsCounter += 1;
				HANDLERS(LocalQp).FlowGenerator.NodeIndex += 1;
				SteeringTree.ListOfNodes.add(NewChild);
				if NewChild.ValueType == AllValues{
					break;
				};
				if NewChild.ParentNodes.has(it.RemoteFlow) {
					NewChild.RemoteFlow = TRUE;
				};
				if RxIPSecHostType != None {
					NewChild.RxIPSecOnInner = RxIPSecOnInner;
					NewChild.RxIPSecHostType = RxIPSecHostType;
				} else {
					gen NewChild.RxIPSecHostType;
					if NewChild.RxIPSecHostType != None {
						NewChild.RxIPSecOnInner = NewChild.Kind in [ETHERNET_NODE_KIND_INNER_WITH_DUMMY];
					};
				};
				if SxIPSecHostType != None {
					NewChild.SxIPSecOnInner = SxIPSecOnInner;
					NewChild.SxIPSecHostType = SxIPSecHostType;
				} else {
					gen NewChild.SxIPSecHostType;
					if NewChild.SxIPSecHostType != None {
						NewChild.SxIPSecOnInner = NewChild.Kind in [ETHERNET_NODE_KIND_INNER_WITH_DUMMY];
					};
				};
				if NewChild.RxIPSecHostType != None or NewChild.SxIPSecHostType != None {
					if RxIPSecMode != None {
						NewChild.RxIPSecMode = RxIPSecMode;
					} else {
						gen NewChild.RxIPSecMode;
					};
					if SxIPSecMode != None {
						NewChild.SxIPSecMode = SxIPSecMode;
					} else {
						gen NewChild.SxIPSecMode;
					};
				};
				if NewChild.RxIPSecHostType != None or NewChild.SxIPSecHostType != None {
					if RxEspMode != None {
						NewChild.RxEspMode = RxEspMode;
					} else {
						gen NewChild.RxEspMode
					};
					if SxEspMode != None {
						NewChild.SxEspMode = SxEspMode;
					} else {
						gen NewChild.SxEspMode;
					};
				};
				if NewChild.RxIPSecHostType != None or NewChild.SxIPSecHostType != None {
					NewChild.IPSecAuthenticationTagLength = IPSecAuthenticationTagLength;
				};
                //MACSec
                if RxMACSecHostType != None {
                    NewChild.RxMACSecHostType = RxMACSecHostType;
                    NewChild.RxMACSecMode = RxMACSecMode;
                    NewChild.RxSecTagSize = RxSecTagSize;
                    NewChild.RxSecTagMode = RxSecTagMode;
                };
                if SxMACSecHostType != None {
                    NewChild.SxMACSecHostType = SxMACSecHostType;
                    NewChild.SxMACSecMode = SxMACSecMode;
                    NewChild.SxSecTagSize = SxSecTagSize;
                    NewChild.SxSecTagMode = SxSecTagMode;
                };
				NewChild.RxSteeringModificationActions.clear();
				NewChild.SxSteeringModificationActions.clear();
				NewChild.InitSteeringInlineActions();
				if NewChild.MulticastNode and NewChild.Kind == MacDummy_0 {
					NewChild.WithRxInlineAction = TRUE;
					NewChild.GenerateRxSteeringInlineActionsIterator();
				} else {
					NewChild.GenerateRxSteeringInlineActions();
					NewChild.GenerateSxSteeringInlineActions();
					gen NewChild.WithRxInlineAction;
					gen NewChild.WithRxModificationActions;
					gen NewChild.WithSxInlineAction;
					gen NewChild.WithSxModificationActions;
					if NewChild.WithRxModificationActions {
						NewChild.GenerateRxSteeringModificationActions();
						if not NewChild.RxSteeringModificationActions.has(it.RxModificationActionType != None) {
							NewChild.RxSteeringModificationActions.clear();
							NewChild.WithRxModificationActions = FALSE;
						};
					};
					if NewChild.WithSxModificationActions {
						NewChild.GenerateSxSteeringModificationActions();
						if not NewChild.SxSteeringModificationActions.has(it.SxModificationActionType != None) {
							NewChild.SxSteeringModificationActions.clear();
							NewChild.WithSxModificationActions = FALSE;
						};
					};
				};
				gen NewChild.SxTransmitNowEnabled;
				gen NewChild.SxTransmitNowDummyEnabled;
				if NewChild.NeedToResetSxTransmitNowEnabledForParents() {
					for each (Node) in NewChild.ParentNodes {
						Node.SxTransmitNowEnabled = FALSE;
					};
				};
			};
		} else { // end node (no children)
			IsEndNode = TRUE;
			RoCE = IsRoce;
			if ParentNodes.HairPinMode.has(it != None) {
				HairPinMode = ParentNodes.HairPinMode.first(it!=None);
			};
			if IsRoce {
				RoceOverVxlanNode = CanBeRoceOverVxlan();
				if RoceOverVxlanNode != NULL {
					Kind = MacByDecap;
					HANDLERS(LocalQp).FlowGenerator.CreateEncapsulatePacket(me,Encapsulation,RoceOverVxlanNode);
				};
			};
		};
		if  Children.size() != 0 {
			HairPinMode = BeHairPinFlow();
			if HairPinMode not in [None] {
				for each (Action) in {RxSteeringModificationActions;Children.RxSteeringModificationActions}.all(it.RxModificationActionType in [PopVlan, PopMpls]) {
					Action.RxModificationActionType = None;
				};
			};
			HANDLERS(LocalQp).FlowGenerator.PublishSteeringNode(me);
			for each (Child) in Children {
				if Child.MaxNumOfChildren > 0 and Child.RssMode != RssGroup{//orik, 1 means only me no need for more children
					Child.BuildTree(SteeringTree,TotalNumOfFlowsCounter,GvmiInfo,Child.MustReWriteInNextChild());
				};
			};
		} else {
			if ParentNodes.HairPinMode.has( it in [IPoIBGW]) {
				HANDLERS(LocalQp).FlowGenerator.GlobalHairPinModeCounterMAC += 1;
				HANDLERS(LocalQp).FlowGenerator.GlobalHairPinModeCounterIB += 1;
			};
			if ParentNodes.HairPinMode.has(it in [EthHairPin]) {
				HANDLERS(LocalQp).FlowGenerator.GlobalHairPinModeCounterMAC += 2;
			};
		};
	};

	TcpRequieredBySteering(SteeringBranch : list of SteeringNode) : bool is {
		result = SteeringBranch.L4Type.has(it == TCP);
	};

	PacketEndWithL4BySteering(SteeringBranch : list of SteeringNode) : bool is {
		result = (SteeringBranch.has(it.Kind in [InnerIpv4_5Tuple,InnerIpv6L4]) and SteeringBranch.has(it.SteeringNodeInDecapsulationEnabledFlow(TRUE))) or
		(SteeringBranch.has(it.Kind in [Ipv4_5TupleByDecap,Ipv6L4ByDecap] and it.SteeringNodeInDecapsulationEnabledFlow(FALSE))) or
		(SteeringBranch.has(it.Kind in [Ipv4_5TupleByDecap,Ipv6L4ByDecap] and not it.SteeringNodeInDecapsulationEnabledFlow(FALSE)) and not SteeringBranch.has(it.Kind == TunnelType)) or
		(SteeringBranch.has(it.Kind in [Ipv4_5Tuple,Ipv6L4]) and not SteeringBranch.has(it.Kind == TunnelType));
	};

	DestPortIsVxlan(SteeringBranch : list of SteeringNode) : bool is {
		result = FALSE;
		if SteeringBranch.has(it.Kind in [Ipv4_5Tuple]) {
			return SteeringBranch.first(it.Kind in [Ipv4_5Tuple]).FieldValue[47:32] in HANDLERS(Config).NetworkPacketConfig.VXLAN_PORTList;
		};
		if SteeringBranch.has(it.Kind in [Ipv6L4]) {
			return SteeringBranch.first(it.Kind in [Ipv6L4]).FieldValue[111:96] in HANDLERS(Config).NetworkPacketConfig.VXLAN_PORTList;
		};
	};

	CanBeDPP() : bool is {
		result = TRUE;
		var SteeringBranch : list of SteeringNode = {ParentNodes;me};
		result = result and PacketEndWithL4BySteering(SteeringBranch);
		result = result and not TcpRequieredBySteering(SteeringBranch);
	};

	CanBeRoceOverVxlan() : SteeringNode is {
		result = NULL;
	};

	MustReWriteInNextChild() : ActionRequired is {
		result = None;
	};

	BeHairPinFlow() : HairPinMode is also {
		if FlowHasActionsThatCanNotAllowHairPin() or RemoteFlow {
			return result;
		};
		if HANDLERS(LocalQp).FlowGenerator.CloseHairPin and HANDLERS(LocalQp).FlowGenerator.CloseIPoIBGW {
			return result;
		};
		if {IsRoce;ParentNodes.IsRoce}.has(it == TRUE) or {RoCE;ParentNodes.RoCE}.has(it == TRUE) or NewChild.RssMode == RssGroup {
			for each (HairPinNode) in ParentNodes.all(it.HairPinMode != None) {
				HairPinNode.HairPinMode = None;
			};
			return result;
		};
		for each (EndNode) in SteeringTree.RootNode.GetAllChildren().all(it.Kind == EndOfTree).all(it.HairPinMode == None)  {
			if not EndNode.GetRxSteeringBranchReWriteActions().has(it.DstDwOffset in [OUTER_SMAC_DEFINER_FIELDS]) {
				break;
			};
		};
		if ParentNodes.HairPinMode.has(it != None) {
			return ParentNodes.HairPinMode.first(it != None) ;
		};
		if (sys.GlobalVariables.PerformanceTest != None and sys.GlobalVariables.PerfTestParameters.Hairpin not in [Bridge,None]) {
			if ((NodeIndex % 2 == 0) and LevelInTree == 1) {
				return EthHairPin;
			};
			if (LevelInTree != 1 and ParentNodes.has(it.HairPinMode in [EthHairPin])) {
				return EthHairPin;
			};
			return None;
		};
		if {RxSteeringModificationActions;ParentNodes.RxSteeringModificationActions}.has(it.RxModificationActionType in [Add,Set,Copy] and it.DstDwOffset in [OUTER_DMAC_DEFINER_FIELDS] and not it.OnInnerPacket) {
			if {RxSteeringModificationActions;ParentNodes.RxSteeringModificationActions}.has(it.RxModificationActionType in [Add,Set,Copy] and it.DstDwOffset in [OUTER_SMAC_DEFINER_FIELDS]) {
				gen result keeping {
					it in [None, EthHairPin];
					read_only(HANDLERS(LocalQp).FlowGenerator.CloseHairPin) => it == None;
				};
				return result;
			};
		};
		if NextNodeType in [Ipv6Dst,Ipv6Src,Ipv4_5Tuple,Ipv6L4] and not {me;ParentNodes}.has(it.Kind == Mpls) {
			gen result keeping {
				it in [None, IPoIBGW];
				read_only(HANDLERS(LocalQp).FlowGenerator.CloseIPoIBGW) => it == None;
				read_only(HANDLERS(LocalQp).FlowGenerator.GlobalHairPinModeCounterIB >= HANDLERS(LocalQp).FlowGenerator.MaxHairPinModeIB or HANDLERS(LocalQp).FlowGenerator.GlobalHairPinModeCounterMAC >= HANDLERS(LocalQp).FlowGenerator.MaxHairPinModeMAC) => it == None;
				read_only(not (TOPOLOGY.GetPortInfoList().has(it.LinkProtocol == IB) and TOPOLOGY.GetPortInfoList().has(it.LinkProtocol == MAC))) => it == None;
			};
		};
	};

	AddChild(NewLevelInTree : uint,Child : SteeringNode) is {
		Child.FatherNode = me;
		Child.LevelInTree = NewLevelInTree;
		Children.add(Child);
	};

	GetRxSteeringBranchReWriteActions() : list of SteeringNodeModificationActions is also {
		result = {};
		for each (SteeringActions) in {ParentNodes;me}.all(it.SteeringNodeHasRewriteActions(RX)) {
			result.add(SteeringActions.RxSteeringModificationActions.all(it.RxModificationActionType in [Add,Set,Copy]));
		};
	};

	GetSxSteeringBranchReWriteActions() : list of SteeringNodeModificationActions is also {
		result = {};
		for each (SteeringActions) in {ParentNodes;me}.all(it.SteeringNodeHasRewriteActions(SX)) {
			result.add(SteeringActions.SxSteeringModificationActions.all(it.SxModificationActionType in [Add,Set,Copy]));
		};
	};

	GetSteeringDWDefinerFieldsAsUint(DwDefinerlist:list of SteeringDWDefinerFields): list of uint is also{
		result = {};
		for each (SteeringDWDefinerFields) in DwDefinerlist{
			result.add(SteeringDWDefinerFields.as_a(uint));
		};
	};

	GetSteeringBranch() : list of SteeringNode is also{
		if RoceOverVXLAN and RoceOverVxlanNode != NULL {
			result = {RoceOverVxlanNode.ParentNodes;RoceOverVxlanNode};
		} else {
			result = {ParentNodes;me};
		};
		result = result.sort_by_field(LevelInTree);
	};

	PrintMe() is also {
		for i from 1 to LevelInTree*4 {
			outf("-");
		};
		outf("Kind=%s, LevelInTree=%s, Children.size()=%s", Kind, LevelInTree, Children.size());
		outf(", NodeIndex=%s, ValueType=%s, IBSteeringMode=%s", NodeIndex, ValueType,IBSteeringMode);
		if (ValueType == CertainValue) {
			PrintAccordingToKind();
		};
		outf(", EndNode=%s, Roce=%s, RoceOverVXLAN=%s", Children.is_empty(), IsRoce,RoceOverVXLAN);
		outf(" %s", L3Type != None ? appendf("L3Type=%s",L3Type) : " ");
		outf(" %s", L4Type != None ? appendf("L4Type=%s",L4Type) : " ");
		outf(" %s", (Kind == TunnelType) ? appendf("TunnelType=%s",SteeringTunnelType) : "");
		outf(" %s", RxIPSecHostType != None ? appendf("RxIPSecHostType=%s RxIPSecOnInner=%s RxIPSecMode=%s RxEspMode=%s",RxIPSecHostType,RxIPSecOnInner,RxIPSecMode,RxEspMode) : " ");
		outf(" %s", SxIPSecHostType != None ? appendf("SxIPSecHostType=%s SxIPSecOnInner=%s SxIPSecMode=%s SxEspMode=%s",SxIPSecHostType,SxIPSecOnInner,SxIPSecMode,SxEspMode) : " ");
        outf(" %s", RxMACSecHostType != None ? appendf("RxMACSecHostType=%s RxMACSecMode=%s RxSecTagSize=%s RxSecTagMode=%s ",RxMACSecHostType,RxMACSecMode,RxSecTagSize,RxSecTagMode) : " ");
        outf(" %s", SxMACSecHostType != None ? appendf("SxMACSecHostType=%s SxMACSecMode=%s SxSecTagSize=%s SxSecTagMode=%s ",SxMACSecHostType,SxMACSecMode, SxSecTagSize, SxSecTagMode) : " ");
        outf(", WithSxInlineAction=%s, WithRxInlineAction=%s, WithSxModificationActions=%s, WithRxModificationActions=%s",WithSxInlineAction,WithRxInlineAction,WithSxModificationActions,WithRxModificationActions);
		if SmacEncapsulationLoopbackType != None {
			outf(", SmacEncapsulationLoopbackType=%s, LoopbackDmac=%s",SmacEncapsulationLoopbackType,LoopbackDmac);
		};
		if DmacEncapsulationLoopbackType != None {
			outf(", DmacEncapsulationLoopbackType=%s, LoopbackSmac=%s",DmacEncapsulationLoopbackType,LoopbackSmac);
		};
		outf(", HairPinMode=%s, RemoteFlow=%s",HairPinMode,RemoteFlow);
		outf(", RssMode=%s", RssMode);
		case RssMode {
			RssGroup : {
				outf(": RssIndex=0x%x, RssSubType=%s, L3Dst=%s, L3Src=%s, SymmetricL3=%s, L4Dst=%s, L4Src=%s, SymmetricL4=%s, NumQps=%s",RssDataBase.RssIndex,RssDataBase.RssSubType,RssDataBase.RssL3Dst, RssDataBase.RssL3Src, RssDataBase.SymmetricIpAddress , RssDataBase.RssL4Dst, RssDataBase.RssL4Src, RssDataBase.SymmetricTcpUdpAddress, RssDataBase.NumOfRssChildrenQps);
			};
			StoreHash : {
				//DUTError(44252,"StoreHashNode ") { outf("NodeIndex = 0x%x",NodeIndex);};
			};
		};
		outf("\n");
		for each (Child) in Children {
			Child.PrintMe();
		};
	};

	PrintAccordingToKind() is {
		case Kind {
			[ALL_MAC_STEERING_TYPE_WITH_DUMMY] : {
				outf(", MyMac=%s,",FieldValue);
			};
			[ALL_VLAN_STEERING_TYPE_WITH_DUMMY] : {
				outf(", Num Of Vlans=%s", VlanList.size());
				for each (aVlan) in VlanList {
					outf(", Vlans[%d]=%s", index, aVlan.AsAString());
				};
			};
			[ALL_MPLS_STEERING_TYPE_WITH_DUMMY] : {
				outf(", Num Of MplsLabels=%s", MplsLabelHeader.MPLSLabelStackList.size());
				for each (MplsLabel) in MplsLabelHeader.MPLSLabelStackList {
					outf(", MplsLabels[%d]=%s", index, MplsLabel.AsAString());
				};
			};
			TunnelType : {
				var TunnelId : uint(bits:32) = FieldValue[63:32];
				outf(", TunnelId=%s",TunnelId);
			};
			[ALL_IPV6DST_STEERING_TYPE_WITH_DUMMY] : {
				var DestIp6Address : uint(bits:128) = FieldValue;
				outf(", Dest Ip6 Address=%s",DestIp6Address);
			};
			[ALL_IPV6SRC_STEERING_TYPE_WITH_DUMMY] : {
				var SrcIp6Address : uint(bits:128) = FieldValue;
				outf(", Source Ip6 Address=%s",SrcIp6Address);
			};
			[ALL_IPV6L4_STEERING_TYPE_WITH_DUMMY] : {
				var DstPort : uint(bits:16) = FieldValue[111:96];
				var SrcPort : uint(bits:16) = FieldValue[79:64];
				outf(", Dest Port=%s, SourcePort=%s",DstPort,SrcPort);
			};
			[ALL_IPV45TUPLE_STEERING_TYPE_WITH_DUMMY] : {
				var DestIp4Address : uint(bits:32) = FieldValue[127:96];
				var SrcIp4Address : uint(bits:32) = FieldValue[95:64];
				var DstPort : uint(bits:16) = FieldValue[47:32];
				var SrcPort : uint(bits:16) = FieldValue[63:48];
				outf(", Dest Ip4 Address=%s,  Source Ipv4 Address=%s, Source Port=%s, Dest Port=%s",DestIp4Address,SrcIp4Address,DstPort,SrcPort);
			};
			[ALL_IPV4DST_STEERING_TYPE_WITH_DUMMY] : {
				var DestIp4Address : uint(bits:32) = FieldValue;
				outf(", Dest Ip4 Address=%s",DestIp4Address);
			};
			[ALL_IPV4SRC_STEERING_TYPE_WITH_DUMMY] : {
				var SrcIp4Address : uint(bits:32) = FieldValue;
				outf(", Source Ip4 Address=%s",SrcIp4Address);
			};
			[ALL_L4ONLY_STEERING_TYPE_WITH_DUMMY] : {
				var DstPort : uint(bits:16) = FieldValue[111:96];
				var SrcPort : uint(bits:16) = FieldValue[79:64];
				outf(", Dest Port=%s, SourcePort=%s",DstPort,SrcPort);
			};
			[ALL_ESP_STEERING_TYPE_WITH_DUMMY] : {
				outf(", Spi=%s",FieldValue[31:0]);
			};
			[Lid] : {
				var Dlid : uint(bits:16) = FieldValue[111:96];
				outf(", Dlid=%s, Lmc=%s",Dlid,Lmc);
			};
			[Gid] : {
				for each (Gid) in DGidList {
					outf(", \nDGid=%s\n",Gid);
				};
			};
			[WredMask] : {
				outf(", WredBuffersMask=%s,",WredBuffersMask);
			};
			default: {
			};
		};
	};

	GenMplsLabels() is {
		gen MplsLabelHeader;
		if FatherNode != NULL and FatherNode.Children.all(it.Kind in [Mpls,MplsByDecap,InnerMpls]).size() > 0x1 {
			gen MplsLabelHeader.MPLSLabelStackList keeping {
				it.size() == read_only(FatherNode.Children.first(it.Kind in [Mpls,MplsByDecap,InnerMpls]).MplsLabelHeader.MPLSLabelStackList.size());
			};
		} else {
			gen MplsLabelHeader.MPLSLabelStackList;
		};
		for each (MplsLabel) in MplsLabelHeader.MPLSLabelStackList {
			gen MplsLabel.Label;
			MplsLabel.BottomOfStack = 0;
			gen MplsLabel.TTL;
			gen MplsLabel.TrafficClass;
		};
	};

	GenVlans() is {
		gen VlanList;
		for each (Vlan) in VlanList{
			var VlanID : uint(bits:12);
			if HANDLERS(Config).VlanIdPool.has(it not in SteeringTree.GeneratedVlanID){
				gen VlanID keeping {
					it in HANDLERS(Config).VlanIdPool;
					it not in SteeringTree.GeneratedVlanID;
				};
			}else{
				gen VlanID keeping {
					it not in SteeringTree.GeneratedVlanID;
				};
			};
			HANDLERS(LocalQp).FlowGenerator.GetUnicastTree(SteeringTree.Port,SteeringTree.Gvmi).GeneratedVlanID.add(VlanID);
			Vlan.VlanID = VlanID;
			gen VlanPrio;
			Vlan.PCP = VlanPrio[3:1];
			Vlan.CFI_DEI = VlanPrio[0:0];
		};
	};

	CheckIfTunnelingNeededAndUpdateParentRelevantFields(Kind : SteeringType) is {
		var VxlanPort : uint;
		gen VxlanPort keeping{
			it in HANDLERS(Config).NetworkPacketConfig.VXLAN_PORTList;
		};
		if Kind == TunnelType and SteeringTunnelType == VXLAN {
			if ParentNodes.has(it.Kind in [Ipv6L4,L4Only]) {
				ParentNodes.first(it.Kind in [Ipv6L4,L4Only]).FieldValue[111:96] = VxlanPort;
			} else if ParentNodes.has(it.Kind in [Ipv4_5Tuple]) {
				ParentNodes.first(it.Kind in [Ipv4_5Tuple]).FieldValue[47:32] = VxlanPort;
			};
		};
	};

	BuildGidSteeringNode(GidList : list of uint (bits : 128)) is {
		if Kind != Gid {
			DUTError(9966,appendf("BuildGidSteeringNode in non Gid Steering node kind: %s",Kind))
		};
		DGidList = GidList;
	};

	GetAllSteeringSides() : list of RxSxType is {
		return {SX;RX};
	};

	BuildMustReWriteAction(OnInnerPacket : bool,MustReWriteAction : ActionRequired) is {
	};

	BuildSteeringNodeByEncapsualtionPacket(EncapsulatedPacket : NetworkPacket) is {
		if ValueType == CertainValue{
			case Kind {
				[Mac] : {
					FieldValue = EncapsulatedPacket.MACHeader().DestAddr;
				};
				[Vlan] : {
					var EncapsulatedVlan : MacInternalHeader;
					EncapsulatedVlan = deep_copy(EncapsulatedPacket.MACHeader().MacInternalHeaders.first(TRUE));
					VlanList.add(EncapsulatedVlan);
					if EncapsulatedPacket.MACHeader().MacInternalHeaders.size() > 1 {
						EncapsulatedVlan = deep_copy(EncapsulatedPacket.MACHeader().MacInternalHeaders[1]);
						VlanList.add(EncapsulatedVlan);
					};
				};
				[Ipv6Dst] : {
					FieldValue = EncapsulatedPacket.IPv6Header().DestGID;
				};
				[Ipv6Src] : {
					FieldValue = EncapsulatedPacket.IPv6Header().SrcGID;
				};
				[Ipv4_5Tuple] : {
					FieldValue[127:96] = EncapsulatedPacket.IPv4Header().DestAddress;
					FieldValue[95:64] = EncapsulatedPacket.IPv4Header().SrcAddress;
					if EncapsulatedPacket.Headers.has(it.HeaderKind == TCP) {
						FieldValue[47:32] = EncapsulatedPacket.TCPHeader().DestPort;
						FieldValue[63:48] = EncapsulatedPacket.TCPHeader().SrcPort;
					} else if EncapsulatedPacket.Headers.has(it.HeaderKind == UDP) {
						FieldValue[47:32] = EncapsulatedPacket.UDPHeader().DestPort;
						FieldValue[63:48] = EncapsulatedPacket.UDPHeader().SrcPort;
					};
				};
				[Ipv6L4] : {
					if EncapsulatedPacket.Headers.has(it.HeaderKind == TCP) {
						FieldValue[111:96] = EncapsulatedPacket.TCPHeader().DestPort;
						FieldValue[79:64] = EncapsulatedPacket.TCPHeader().SrcPort;
					} else if EncapsulatedPacket.Headers.has(it.HeaderKind == UDP) {
						FieldValue[111:96] = EncapsulatedPacket.UDPHeader().DestPort;
						FieldValue[79:64] = EncapsulatedPacket.UDPHeader().SrcPort;
					};
				};
			};
		};
		case RssMode {
			RssGroup : {
				gen RssDataBase;
				RssDataBase.Gvmi = SteeringTree.Gvmi;
				RssDataBase.Port = SteeringTree.Port;
				if sys.GlobalVariables.PerformanceTest != None and sys.GlobalVariables.PerfTestParameters.TransportService in [ETH, RC] and Kind != Mac {
					RssDataBase.NumOfRssChildrenQps = MaxNumOfChildren;
				} else {
					var QpIndexLength : uint = (3 - RssDataBase.QpnSize)*8;
					if RssDataBase.QpnSize in [1,2] {
						QpIndexLength -= HANDLERS(Config).CrSpaceConfig.Log2NumberOfEntriesInGvmiList;
					};
					var MaxNumOfRssQpNumbers : uint = (1 << QpIndexLength-1)-1;
					if (MaxNumOfChildren - 1) > MaxNumOfRssQpNumbers {
						RssDataBase.NumOfRssChildrenQps = MaxNumOfRssQpNumbers;
					} else {
						RssDataBase.NumOfRssChildrenQps = MaxNumOfChildren - 1;
					};
				};
				if HANDLERS(Config).ParentGvmiPciLinkList.first(it.ParentGvmiNumPciLink.GvmiNum == SteeringTree.Gvmi).ChildrenGvmiNumPciLink.all(it.NetworkPort == RssDataBase.Port).size() > 0 {
					RssDataBase.RssOnMultiGvmi = TRUE;
				};
				RssDataBase.RssIndex = HANDLERS(LocalQp).FlowGenerator.RssDataBaseCounter;
				gen RssDataBase.SymmetricIpAddress;
				gen RssDataBase.SymmetricTcpUdpAddress;
				RssIndex = RssDataBase.RssIndex;
				messagef(MEDIUM,"Created Rss group: SymmetricIpAddress=%s, SymmetricTcpUdpAddress=%s, RssSubType=%s, L3 Dst=%s, L3 Src=%s, L4 Dst=%s, L4 Src=%s, index=%s, Gvmi=%s, Port=%s, num of children Qps=%s",
					RssDataBase.SymmetricIpAddress,RssDataBase.SymmetricTcpUdpAddress,RssDataBase.RssSubType,RssDataBase.RssL3Dst,RssDataBase.RssL3Src,RssDataBase.RssL4Dst,RssDataBase.RssL4Src,RssDataBase.RssIndex,SteeringTree.Gvmi,SteeringTree.Port,RssDataBase.NumOfRssChildrenQps);
				HANDLERS(LocalQp).FlowGenerator.RssDataBaseCounter += 1;
				HANDLERS(LocalQp).FlowGenerator.NumOfRssQps += RssDataBase.NumOfRssChildrenQps;
				HANDLERS(LocalQp).FlowGenerator.RssDataBaseList.add(RssDataBase);
			};
			StoreHash :{
				DUTError(44252,"StoreHashNode") {
					PrintMe();
				};
			};
			default : {
			};
		};
	};

	BuildSteeringNode() is {
		if ValueType == CertainValue{
			var NotAllowedDestPort : list of uint(bits:16) = {HANDLERS(Config).NetworkPacketConfig.BTHOverUDP_PORT;HANDLERS(Config).NetworkPacketConfig.GenericEncapPropertiesList.UdpDport;HANDLERS(Config).NetworkPacketConfig.VXLAN_PORTList};
			EntryNodeValueForMatch = HANDLERS(LocalQp).FlowGenerator.EntryNodeValueGenerator.GenNum();
			case Kind {
				[Vlan,VlanByDecap,InnerVlan] : {
					GenVlans();
				};
				[Mpls,MplsByDecap,InnerMpls] : {
					GenMplsLabels();
				};
				[Ipv6Dst,Ipv6DstByDecap,InnerIpv6Dst] : {
					if MulticastNode {
						FieldValue = MulticastGroup.Dgid;
					} else {
						FieldValue = HANDLERS(LocalQp).FlowGenerator.Ipv6DestAddressGenerator.GenNum();
						if HANDLERS(LocalQp).FlowGenerator.PatchToAvoidHashAfterActions {
							if Kind == Ipv6DstByDecap and ParentNodes.first(it.Kind == TunnelType).RxSteeringModificationActions.has(it.RxModificationActionType == L3DecapEnable) {
								FieldValue = ParentNodes.first(it.Kind == Ipv6Dst).FieldValue;
							};
						};
					};
				};
				[Ipv6Src,Ipv6SrcByDecap,InnerIpv6Src] : {
					FieldValue = HANDLERS(LocalQp).FlowGenerator.Ipv6SourceAddressGenerator.GenNum();
				};
				[Ipv6L4,Ipv6L4ByDecap,InnerIpv6L4,L4Only,L4OnlyByDecap,InnerL4Only] : {
					FieldValue[111:96] = HANDLERS(LocalQp).FlowGenerator.TcpUdpPortGenerator.GenNum();
					FieldValue[79:64] = HANDLERS(LocalQp).FlowGenerator.TcpUdpPortGenerator.GenNum();

					FieldValue[111:96] = HANDLERS(LocalQp).FlowGenerator.TcpUdpPortGenerator.GenNum();
					while NotAllowedDestPort.has(it == FieldValue[111:96]) {
						FieldValue[111:96] = HANDLERS(LocalQp).FlowGenerator.TcpUdpPortGenerator.GenNum();
					};
					FieldValue[79:64] = HANDLERS(LocalQp).FlowGenerator.TcpUdpPortGenerator.GenNum();
					while NotAllowedDestPort.has(it == FieldValue[79:64]) {
						FieldValue[79:64] = HANDLERS(LocalQp).FlowGenerator.TcpUdpPortGenerator.GenNum();
					};
				};
				[Ipv4_5Tuple,Ipv4_5TupleByDecap,InnerIpv4_5Tuple] : {
					FieldValue[127:96] = HANDLERS(LocalQp).FlowGenerator.Ipv4DestAddressGenerator.GenNum();
					FieldValue[95:64] = HANDLERS(LocalQp).FlowGenerator.Ipv4SourceAddressGenerator.GenNum();

					FieldValue[63:48] = HANDLERS(LocalQp).FlowGenerator.TcpUdpPortGenerator.GenNum();
					while NotAllowedDestPort.has(it == FieldValue[63:48]) {
						FieldValue[63:48] = HANDLERS(LocalQp).FlowGenerator.TcpUdpPortGenerator.GenNum();
					};
					FieldValue[47:32] = HANDLERS(LocalQp).FlowGenerator.TcpUdpPortGenerator.GenNum();
					while NotAllowedDestPort.has(it == FieldValue[47:32]) {
						FieldValue[47:32] = HANDLERS(LocalQp).FlowGenerator.TcpUdpPortGenerator.GenNum();
					};
				};
				[Ipv4Dst,Ipv4DstByDecap,InnerIpv4Dst] : {
					FieldValue = HANDLERS(LocalQp).FlowGenerator.Ipv4DestAddressGenerator.GenNum();
					if HANDLERS(LocalQp).FlowGenerator.PatchToAvoidHashAfterActions {
						if Kind == Ipv4DstByDecap and ParentNodes.first(it.Kind == TunnelType).RxSteeringModificationActions.has(it.RxModificationActionType == L3DecapEnable) {
							FieldValue = ParentNodes.first(it.Kind == Ipv4Dst).FieldValue;
						};
					};
				};
				[Ipv4Src,Ipv4SrcByDecap,InnerIpv4Src] : {
					FieldValue = HANDLERS(LocalQp).FlowGenerator.Ipv4SourceAddressGenerator.GenNum();
				};
				TunnelType : {
					if FatherNode.Children.size() > 1 { // Not the first TunnelType
						SteeringTunnelType = FatherNode.Children[0].SteeringTunnelType;
					} else {
						if ParentNodes.has(it.Kind in [Ipv4_5Tuple,Ipv6L4,L4Only]) {
							SteeringTunnelType = VXLAN;
						} else {
							gen SteeringTunnelType keeping {
								it not in [None];
							};
						};
					};
					FieldValue[63:32] = HANDLERS(LocalQp).FlowGenerator.TunnelIdGenerator.GenNum();
					if not sys.GlobalVariables.GoodMachineTest { // in non GoodTest TunnelId = 0x0 may cause error flows to non error one
						while FieldValue[63:32] == 0x0 {
							FieldValue[63:32] = HANDLERS(LocalQp).FlowGenerator.TunnelIdGenerator.GenNum();
						};
					};
					CheckIfTunnelingNeededAndUpdateParentRelevantFields(Kind);
				};
				[Mac,MacByDecap,InnerMac] : {
					HANDLERS(LocalQp).FlowGenerator.HandleMacRoot(me);
					if HANDLERS(LocalQp).FlowGenerator.PatchToAvoidHashAfterActions {
						if Kind == MacByDecap {
							FieldValue = ParentNodes.first(it.Kind == Mac).FieldValue;
						};
					};
				};
				WredMask : {
					FieldValue = ParentNodes.first(it.Kind == Mac).FieldValue;
					gen WredBuffersMask keeping {
						it in [0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80];
					};
				};
				[Esp,EspByDecap,InnerEsp] : {
					FieldValue[31:0] = HANDLERS(LocalQp).FlowGenerator.SpiGenerator.GenNum();
				};
				[Gid,Lid] : {
					DUTError(9556,appendf("BuildSteeringNode for Gid Lid Steering node kind: %s",Kind));
				};
				[DUMMY_STEERING_TYPE] : {
					var DummyIndex : uint = Kind in [DUMMY0_STEERING_TYPE] ? 0x0 : (Kind in [DUMMY1_STEERING_TYPE] ? 0x1 : (Kind in [DUMMY2_STEERING_TYPE] ? 0x2 : 0x3));
					var ParentNodesWithOutDummy : list of SteeringNode = ParentNodes.all(it.Kind in [STEERING_TYPE_HAS_DUMMY]);
					FieldValue = ParentNodesWithOutDummy.first(Kind == appendf("%sDummy_%d",it.Kind,DummyIndex).as_a(SteeringType)).FieldValue;
				};
				[STEERING_REGISTER_TYPES] : {
					FieldValue[127:64] = (Kind == Register0) ? RxRegister0Value : (Kind == Register1) ? RxRegister1Value : (Kind == Register2) ? RxRegister2Value : (Kind == Register3) ? RxRegister3Value : (Kind == Register4) ? RxRegister4Value : RxRegister5Value;
					FieldValue[63:0]   = (Kind == Register0) ? SxRegister0Value : (Kind == Register1) ? SxRegister1Value : (Kind == Register2) ? SxRegister2Value : (Kind == Register3) ? SxRegister3Value : (Kind == Register4) ? SxRegister4Value : SxRegister5Value;
				};
				EndOfTree : {
					//do nothing
				};
				default : {
					DUTError(9356,appendf("unknown  Steering node kind: %s",Kind))
				};
			};
		};
		case RssMode {
			[RssGroup,StoreHash] : {
				gen RssDataBase;
				RssDataBase.Gvmi = SteeringTree.Gvmi;
				RssDataBase.Port = SteeringTree.Port;
				if RssMode == RssGroup {
					var ConfigRequirements : ConfigRequirements = new with {
						.PortNum = SteeringTree.Port;
						.GvmiNum = SteeringTree.Gvmi;
					};
					var GvmiContext : GvmiContext = HANDLERS(Config).GetGvmiContext(ConfigRequirements);
					if HANDLERS(Config).ParentGvmiPciLinkList.first(it.ParentGvmiNumPciLink.GvmiNum == SteeringTree.Gvmi).ChildrenGvmiNumPciLink.all(it.NetworkPort == RssDataBase.Port).size() > 0 {
						RssDataBase.RssOnMultiGvmi = TRUE;
						gen RssDataBase.QpnSize;
					};
					if sys.GlobalVariables.PerformanceTest != None and sys.GlobalVariables.PerfTestParameters.TransportService in [ETH, RC] and Kind != Mac {
						RssDataBase.NumOfRssChildrenQps = MaxNumOfChildren;
					} else {
						var QpIndexLength : uint = (3 - RssDataBase.QpnSize)*8;
						if RssDataBase.QpnSize in [1,2] {
							QpIndexLength -= HANDLERS(Config).CrSpaceConfig.Log2NumberOfEntriesInGvmiList;
						};
						var MaxNumOfRssQpNumbers : uint = (1 << QpIndexLength-1)-1;
						if (MaxNumOfChildren - 1) > MaxNumOfRssQpNumbers {
							RssDataBase.NumOfRssChildrenQps = MaxNumOfRssQpNumbers;
						} else {
							RssDataBase.NumOfRssChildrenQps = MaxNumOfChildren - 1;
						};
					};
				};
				RssDataBase.RssIndex = HANDLERS(LocalQp).FlowGenerator.RssDataBaseCounter;
				gen RssDataBase.SymmetricIpAddress;
				gen RssDataBase.SymmetricTcpUdpAddress;
				RssIndex = RssDataBase.RssIndex;
				messagef(MEDIUM,"Created Rss group: SymmetricIpAddress=%s, SymmetricTcpUdpAddress=%s, RssSubType=%s, L3 Dst=%s, L3 Src=%s, L4 Dst=%s, L4 Src=%s, index=%s, RssOnMultiGvmi=%s, Gvmi=%s, Port=%s, num of children Qps=%s, NumberOfEntriesInGvmiList=%s",
					RssDataBase.SymmetricIpAddress,RssDataBase.SymmetricTcpUdpAddress,RssDataBase.RssSubType,RssDataBase.RssL3Dst,RssDataBase.RssL3Src,RssDataBase.RssL4Dst,RssDataBase.RssL4Src,RssDataBase.RssIndex,RssDataBase.RssOnMultiGvmi,SteeringTree.Gvmi,SteeringTree.Port,RssDataBase.NumOfRssChildrenQps,RssDataBase.NumberOfEntriesInGvmiList);
				HANDLERS(LocalQp).FlowGenerator.RssDataBaseCounter += 1;
				HANDLERS(LocalQp).FlowGenerator.NumOfRssQps += RssDataBase.NumOfRssChildrenQps;
				HANDLERS(LocalQp).FlowGenerator.RssDataBaseList.add(RssDataBase);
			};
			default : {
			};
		};
	};

	GetMaxSxTagDataSize() : uint is {
		var ConfigRequirements : ConfigRequirements = new with {
			.PortNum = SteeringTree.Port;
			.GvmiNum = SteeringTree.Gvmi;
		};
		var GvmiContext : GvmiContext = HANDLERS(Config).GetGvmiContext(ConfigRequirements);
		return GvmiContext.SxTagDataSize;
	};

	EtherTypeToVlanQualifier(EtherType : uint(bits:16)) : uint(bits:2) is also{
		case EtherType {
			[CVLAN_ETHERTYPE_SPEC] : {return 2;};
			[0x88a8] : { return 1;};
			default : { return 3;};
		};
	};

	GetVlanValue(VlanFieldValue : SteeringDefinerFields) : uint is also{
		case VlanFieldValue {
			[OuterEthL2_FirstVlanQualifier,InnerEthL2_FirstVlanQualifier] : {
				return EtherTypeToVlanQualifier(VlanList[0].EtherType);
			};
			[OuterEthL2_SecondVlanQualifier,InnerEthL2_SecondVlanQualifier] : {
				return EtherTypeToVlanQualifier(VlanList[1].EtherType);
			};
			[OuterEthL2_FirstVlanPrio,InnerEthL2_FirstVlanPrio] : {
				return VlanList[0].PCP;
			};
			[OuterEthL2_SecondVlanPrio,InnerEthL2_SecondVlanPrio] : {
				return VlanList[1].PCP;
			};
			[OuterEthL2_FirstVlanCFI,InnerEthL2_FirstVlanCFI] : {
				return VlanList[0].CFI_DEI;
			};
			[OuterEthL2_SecondVlanCFI,InnerEthL2_SecondVlanCFI] : {
				return VlanList[1].CFI_DEI;
			};
			[OuterEthL2_FirstVlanId_11_8,InnerEthL2_FirstVlanId_11_8] : {
				return VlanList[0].VlanID[11:8];
			};
			[OuterEthL2_SecondVlanId_11_8,InnerEthL2_SecondVlanId_11_8] : {
				return VlanList[1].VlanID[11:8];
			};
			[OuterEthL2_FirstVlanId_7_0,InnerEthL2_FirstVlanId_7_0] : {
				return VlanList[0].VlanID[7:0];
			};
			[OuterEthL2_SecondVlanId_7_0,InnerEthL2_SecondVlanId_7_0] : {
				return VlanList[1].VlanID[7:0];
			};
		};
	};

	GetMplsValue(MplsFieldValue : SteeringDefinerFields) : uint is also{
		case MplsFieldValue {
			[FirstMpls0Qualifier,SecondMpls0Qualifier] : {
				return 1;
			};
			[FirstMpls1Qualifier,SecondMpls1Qualifier] : {
				return 1;
			};
			[FirstMpls2Qualifier,SecondMpls2Qualifier] : {
				return 1;
			};
			[FirstMpls3Qualifier,SecondMpls3Qualifier] : {
				return 1;
			};
			[FirstMpls4Qualifier,SecondMpls4Qualifier] : {
				return 1;
			};
			[FirstMpls0SBit,SecondMpls0SBit] : {
				return MplsLabelHeader.MPLSLabelStackList[0].BottomOfStack;
			};
			[FirstMpls1SBit,SecondMpls1SBit] : {
				return MplsLabelHeader.MPLSLabelStackList[1].BottomOfStack;
			};
			[FirstMpls2SBit,SecondMpls2SBit] : {
				return MplsLabelHeader.MPLSLabelStackList[2].BottomOfStack;
			};
			[FirstMpls3SBit,SecondMpls3SBit] : {
				return MplsLabelHeader.MPLSLabelStackList[3].BottomOfStack;
			};
			[FirstMpls4SBit,SecondMpls4SBit] : {
				return MplsLabelHeader.MPLSLabelStackList[4].BottomOfStack;
			};
			[OuterMpls0_Label,InnerMpls0_Label] : {
				return %{MplsLabelHeader.MPLSLabelStackList[0].Label,MplsLabelHeader.MPLSLabelStackList[0].TrafficClass,MplsLabelHeader.MPLSLabelStackList[0].BottomOfStack,MplsLabelHeader.MPLSLabelStackList[0].TTL};
			};
			[OuterMpls1_Label,InnerMpls1_Label] : {
				return %{MplsLabelHeader.MPLSLabelStackList[1].Label,MplsLabelHeader.MPLSLabelStackList[1].TrafficClass,MplsLabelHeader.MPLSLabelStackList[1].BottomOfStack,MplsLabelHeader.MPLSLabelStackList[1].TTL};
			};
			[OuterMpls2_Label,InnerMpls2_Label] : {
				return %{MplsLabelHeader.MPLSLabelStackList[2].Label,MplsLabelHeader.MPLSLabelStackList[2].TrafficClass,MplsLabelHeader.MPLSLabelStackList[2].BottomOfStack,MplsLabelHeader.MPLSLabelStackList[2].TTL};
			};
			[OuterMpls3_Label,InnerMpls3_Label] : {
				return %{MplsLabelHeader.MPLSLabelStackList[3].Label,MplsLabelHeader.MPLSLabelStackList[3].TrafficClass,MplsLabelHeader.MPLSLabelStackList[3].BottomOfStack,MplsLabelHeader.MPLSLabelStackList[3].TTL};
			};
			[OuterMpls4_Label,InnerMpls4_Label] : {
				return %{MplsLabelHeader.MPLSLabelStackList[4].Label,MplsLabelHeader.MPLSLabelStackList[4].TrafficClass,MplsLabelHeader.MPLSLabelStackList[4].BottomOfStack,MplsLabelHeader.MPLSLabelStackList[4].TTL};
			};
			MplsOKs_FirstMplsOk : {
				return 1;
			};
			MplsOKs_SecondMplsOk : {
				return 1;
			};
		};
	};

	UpdateSteeringParamActions(SteeringParams) is also {
		var SteeringBranch : list of SteeringNode = GetSteeringBranch();
		for each (RxModificationNode) in SteeringBranch.all(it.WithRxModificationActions) {
			for each (RxAction) in RxModificationNode.RxSteeringModificationActions.all(it.RxModificationActionType != None) {
				var RxSteeringParamAction : SteeringNodeModificationActions = new;
				RxSteeringParamAction = RxAction.copy();
				RxSteeringParamAction.ActionLevel = RxModificationNode.LevelInTree;
				if RxSteeringParamAction.OnInnerPacket {
					SteeringParams.InnerSteeringParams.RxSteeringModificationActions.add(RxSteeringParamAction);
				} else {
					SteeringParams.RxSteeringModificationActions.add(RxSteeringParamAction);
				};
			};
		};
		if not RoceOverVXLAN {
			for each (SxModificationNode) in SteeringBranch.all(it.WithSxModificationActions) {
				for each (SxAction) in SxModificationNode.SxSteeringModificationActions.all(it.SxModificationActionType != None) {
					var SxSteeringParamAction : SteeringNodeModificationActions = new;
					SxSteeringParamAction = SxAction.copy();
					SxSteeringParamAction.ActionLevel = SxModificationNode.LevelInTree;
					if SxSteeringParamAction.OnInnerPacket {
						SteeringParams.InnerSteeringParams.SxSteeringModificationActions.add(SxSteeringParamAction);
					} else {
						SteeringParams.SxSteeringModificationActions.add(SxSteeringParamAction);
					};
				};
			};
		};
		if SteeringParams.RxSteeringModificationActions.all(it.RxModificationActionType == PopVlan).size() > 2 or SteeringParams.InnerSteeringParams.RxSteeringModificationActions.all(it.RxModificationActionType == PopVlan).size() > 2 {
			DUTError(8899,appendf("UpdateSteeringParamActions SteeringBranch has %s NumberOfRxVlansToPop and %s Inner NumberOfRxVlansToPop",SteeringParams.RxSteeringModificationActions.all(it.RxModificationActionType == PopVlan).size(),SteeringParams.InnerSteeringParams.RxSteeringModificationActions.all(it.RxModificationActionType == PopVlan).size()));
		};

		for each (RxInlineNode) in SteeringBranch.all(it.WithRxInlineAction) {
			for each (RxInlineAction) in RxInlineNode.RxSteeringInlineActions.all(it.RxInlineActionType != None) {
				var RxSteeringParamAction : SteeringNodeInlineActions = new;
				RxSteeringParamAction = RxInlineAction.copy();
				RxSteeringParamAction.ActionLevel = RxInlineNode.LevelInTree;
				if RxSteeringParamAction.OnInnerPacket {
					SteeringParams.InnerSteeringParams.RxSteeringInlineActions.add(RxSteeringParamAction);
				} else {
					SteeringParams.RxSteeringInlineActions.add(RxSteeringParamAction);
				};
			};
		};

		for each (SxInlineNode) in SteeringBranch.all(it.WithSxInlineAction) {
			for each (SxInlineAction) in SxInlineNode.SxSteeringInlineActions.all(it.SxInlineActionType != None) {
				var SxSteeringParamAction : SteeringNodeInlineActions = new;
				SxSteeringParamAction = SxInlineAction.copy();
				SxSteeringParamAction.ActionLevel = SxInlineNode.LevelInTree;
				if SxSteeringParamAction.OnInnerPacket {
					SteeringParams.InnerSteeringParams.SxSteeringInlineActions.add(SxSteeringParamAction);
				} else {
					SteeringParams.SxSteeringInlineActions.add(SxSteeringParamAction);
				};
			};
		};
	};

	GetPrioFromSteeringNodeIPSecEncapPacket(Port : uint, Direction: NetworkPacketDirection) : uint(bits:4) is also {
		var EncapIPSecAction : SteeringNodeModificationActions = {me;ParentNodes}.SxSteeringModificationActions.first(it.SxModificationActionType == InsertWithPointer and it.Attributes == push_esp);
		if EncapIPSecAction == NULL {
			messagef(HIGH,"GetPrioFromSteeringNodeIPSecEncapPacket: Node:%s (NodeIndex:0x%x) with Port:0x%x returned 0x%x since no ipsec action",me,NodeIndex,Port,0xf);
			return 0xf;
		};
		var EncapsulatedPacket : list of byte = EncapIPSecAction.DataToPush;
		var UnpackedEncapsulatedPacket : NetworkPacket = new;
		UnpackedEncapsulatedPacket.SetDontCheckOnUnpack();
		compute UnpackedEncapsulatedPacket.Unpack(EncapsulatedPacket, MAC, FALSE);
		var PacketPrio : uint(bits:3) = UnpackedEncapsulatedPacket.GetPrioForBufferQueueCalc(Port, Direction); -- Remote->Local flow only, encap is added in Remote
		messagef(HIGH,"GetPrioFromSteeringNodeIPSecEncapPacket: Node:%s (NodeIndex:0x%x) with Port:0x%x returned 0x%x by packet prio",me,NodeIndex,Port,PacketPrio);
		return PacketPrio;
	};

	GetPrioFromSteeringNodeLastEncapPacket(Port : uint, Direction: NetworkPacketDirection) : uint(bits:4) is also {
		var PortConfigs: PortConfigInfo = HANDLERS(Config).GetPortConfigInfo(Port);
		var PrioSourceType: PrioSourceType = Direction == Inbound ? PortConfigs.PrioInfo.RxPrioSourceType : PortConfigs.PrioInfo.SxPrioSourceType;
		var LastEncapAction : SteeringNodeModificationActions = {me;ParentNodes}.SxSteeringModificationActions.last((it.SxModificationActionType in [InsertWithPointer, L3Encapsulation, Encapsulation] and it.Attributes in [push_esp, encap_field_update]) or (it.SxModificationActionType in [PushVlan] and PrioSourceType in [VlanDefault]) or (it.SxModificationActionType in [PushMpls] and PrioSourceType in [MplsExpDscpDefault]));
        if SxMACSecHostType != None and (SxSecTagMode == OverSrcAddr or PrioSourceType not in [VlanDefault]) {
            return  HANDLERS(Config).GetLogicalPortConfigInfoList().key(SteeringTree.Port).PrioInfo.DefaultPrio
        };
		if LastEncapAction == NULL {
			messagef(HIGH,"GetPrioFromSteeringNodeLastEncapPacket: Node:%s (NodeIndex:0x%x) with Port:0x%x returned 0x%x since no ipsec action",me,NodeIndex,Port,0xf);
			return 0xf;
		};
		if LastEncapAction.SxModificationActionType == PushVlan {
			return LastEncapAction.SxPushVlans[0].PCP;
		};
		if LastEncapAction.SxModificationActionType == PushMpls {
			var ConfigRequirements = new with {
				.PortNum = Port
			};
			return HANDLERS(Config).Mpls2Prio(ConfigRequirements, LastEncapAction.MplsLabelsToPush[0].TrafficClass);
		};
		var EncapsulatedPacket : list of byte = LastEncapAction.DataToPush;
		var UnpackedEncapsulatedPacket : NetworkPacket = new;
		UnpackedEncapsulatedPacket.SetDontCheckOnUnpack();
		compute UnpackedEncapsulatedPacket.Unpack(EncapsulatedPacket, MAC, FALSE);
		var PacketPrio : uint(bits:3) = UnpackedEncapsulatedPacket.GetPrioForBufferQueueCalc(Port, Direction); -- Remote->Local flow only, encap is added in Remote
		messagef(HIGH,"GetPrioFromSteeringNodeLastEncapPacket: Node:%s (NodeIndex:0x%x) with Port:0x%x returned 0x%x by packet prio",me,NodeIndex,Port,PacketPrio);
		return PacketPrio;
	};

	GetValidHdsAnchorValuesFromSteeringBranch() : steering_anchor_enum is {
		var ListOfValidAnchors : list of steering_anchor_enum;
		for each (Kind) in {me;ParentNodes}.Kind {
			case Kind {
				[MAC_STEERING_TYPE_WITH_DUMMY,MAC_BY_DECAP_STEERING_TYPE_WITH_DUMMY ] : {
					ListOfValidAnchors.add(mac);
				};
				[INNER_MAC_STEERING_TYPE_WITH_DUMMY] : {
					ListOfValidAnchors.add(inner_mac);
				};
				[VLAN_STEERING_TYPE_WITH_DUMMY,VLAN_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
					ListOfValidAnchors.add({vlan0;vlan1});
				};

				[MPLS_STEERING_TYPE_WITH_DUMMY,MPLS_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
					ListOfValidAnchors.add({mpls0});
				};
				[IPV6DST_STEERING_TYPE_WITH_DUMMY, IPV6SRC_STEERING_TYPE_WITH_DUMMY,
					IPV6DST_BY_DECAP_STEERING_TYPE_WITH_DUMMY, IPV6SRC_BY_DECAP_STEERING_TYPE_WITH_DUMMY   ]  : {
					ListOfValidAnchors.add(ip);
				};

				[IPV6L4_STEERING_TYPE_WITH_DUMMY, IPV45TUPLE_STEERING_TYPE_WITH_DUMMY, L4ONLY_STEERING_TYPE_WITH_DUMMY,
					IPV45TUPLE_BY_DECAP_STEERING_TYPE_WITH_DUMMY, IPV6L4_BY_DECAP_STEERING_TYPE_WITH_DUMMY, L4ONLY_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
					ListOfValidAnchors.add(ip);
					ListOfValidAnchors.add(l4);
				};
				[IPV4DST_STEERING_TYPE_WITH_DUMMY ,IPV4SRC_STEERING_TYPE_WITH_DUMMY,
					IPV4DST_BY_DECAP_STEERING_TYPE_WITH_DUMMY, IPV4SRC_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
					ListOfValidAnchors.add(ip);
				};
				[INNER_VLAN_STEERING_TYPE_WITH_DUMMY] : {
					ListOfValidAnchors.add(inner_vlan0);
					ListOfValidAnchors.add(inner_vlan1);
				};
				[INNER_MPLS_STEERING_TYPE_WITH_DUMMY] : {
					ListOfValidAnchors.add(inner_mpls0);
				};
				[INNER_IPV6DST_STEERING_TYPE_WITH_DUMMY, INNER_IPV6SRC_STEERING_TYPE_WITH_DUMMY,
					INNER_IPV4DST_STEERING_TYPE_WITH_DUMMY, INNER_IPV4SRC_STEERING_TYPE_WITH_DUMMY]  : {
					ListOfValidAnchors.add(inner_ip);
				};
				[INNER_IPV45TUPLE_STEERING_TYPE_WITH_DUMMY, INNER_IPV6L4_STEERING_TYPE_WITH_DUMMY,
					INNER_L4ONLY_STEERING_TYPE_WITH_DUMMY] : {
					ListOfValidAnchors.add(inner_ip);
					ListOfValidAnchors.add(inner_l4);
				};
			};
		};
		if not ListOfValidAnchors.is_empty() {
			gen result keeping {it in ListOfValidAnchors;}
		};
	};
	GetValidHdsOffsetAccordingToAnchor() : byte is {
		gen result;
		case HdsAnchor {
			ip :{
				if {me;ParentNodes}.Kind.has(it in  [IPV6DST_STEERING_TYPE_WITH_DUMMY, IPV6SRC_STEERING_TYPE_WITH_DUMMY,
						IPV6DST_BY_DECAP_STEERING_TYPE_WITH_DUMMY, IPV6SRC_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
						IPV6L4_STEERING_TYPE_WITH_DUMMY,IPV6L4_BY_DECAP_STEERING_TYPE_WITH_DUMMY  ]
				) {
					result = IPV6_HDR_LEN;
				};
				if {me;ParentNodes}.Kind.has(it in  [IPV4DST_STEERING_TYPE_WITH_DUMMY ,IPV4SRC_STEERING_TYPE_WITH_DUMMY,
						IPV4DST_BY_DECAP_STEERING_TYPE_WITH_DUMMY, IPV4SRC_BY_DECAP_STEERING_TYPE_WITH_DUMMY,
						IPV45TUPLE_BY_DECAP_STEERING_TYPE_WITH_DUMMY, IPV45TUPLE_STEERING_TYPE_WITH_DUMMY]
				) {
					result = IPV4_HDR_LEN;
				};
			};
			inner_ip : {
				if {me;ParentNodes}.Kind.has(it in  [INNER_IPV6DST_STEERING_TYPE_WITH_DUMMY, INNER_IPV6SRC_STEERING_TYPE_WITH_DUMMY,
						INNER_IPV6L4_STEERING_TYPE_WITH_DUMMY]
				) {
					result = IPV6_HDR_LEN;
				};

				if {me;ParentNodes}.Kind.has(it in  [INNER_IPV4DST_STEERING_TYPE_WITH_DUMMY, INNER_IPV4SRC_STEERING_TYPE_WITH_DUMMY,
						INNER_IPV45TUPLE_STEERING_TYPE_WITH_DUMMY]
				) {
					result = IPV4_HDR_LEN;
				};
			};
			l4 : {
				if {me;ParentNodes}.Kind.has(it in [IPV6L4_STEERING_TYPE_WITH_DUMMY, IPV45TUPLE_STEERING_TYPE_WITH_DUMMY, L4ONLY_STEERING_TYPE_WITH_DUMMY,
						IPV45TUPLE_BY_DECAP_STEERING_TYPE_WITH_DUMMY, IPV6L4_BY_DECAP_STEERING_TYPE_WITH_DUMMY, L4ONLY_BY_DECAP_STEERING_TYPE_WITH_DUMMY]
				){
					var L4Type = {me;ParentNodes}.last(it.Kind in [IPV6L4_STEERING_TYPE_WITH_DUMMY, IPV45TUPLE_STEERING_TYPE_WITH_DUMMY, L4ONLY_STEERING_TYPE_WITH_DUMMY,
							IPV45TUPLE_BY_DECAP_STEERING_TYPE_WITH_DUMMY, IPV6L4_BY_DECAP_STEERING_TYPE_WITH_DUMMY, L4ONLY_BY_DECAP_STEERING_TYPE_WITH_DUMMY]).L4Type;
					result = (L4Type == TCP) ? TCP_HDR_LEN : UDP_HDR_LEN;
				};
			};
			inner_l4 : {
				if {me;ParentNodes}.Kind.has(it in [INNER_IPV6L4_STEERING_TYPE_WITH_DUMMY, INNER_IPV45TUPLE_STEERING_TYPE_WITH_DUMMY, INNER_L4ONLY_STEERING_TYPE_WITH_DUMMY]){
					var L4Type = {me;ParentNodes}.last(it.Kind in [INNER_IPV6L4_STEERING_TYPE_WITH_DUMMY, INNER_IPV45TUPLE_STEERING_TYPE_WITH_DUMMY, INNER_L4ONLY_STEERING_TYPE_WITH_DUMMY]).L4Type;
					result = (L4Type == TCP) ? TCP_HDR_LEN : UDP_HDR_LEN;
				};
			};
			[mac,inner_mac] : {
				result = MAC_HEADER_LEN;
			};
			[vlan0, vlan1, inner_vlan0, inner_vlan1] : {
				result = VLAN_LEN
			};
			[mpls0, inner_mpls0] : {
				result = MPLS_LEN;
			};
		};
	};
	GenValidHdsAnchorValue() : uint is {
		gen HdsAnchor;
		gen HdsOffset;
		result = 0;
		result[7: 0] = HdsOffset;
		result[21 : 16] = HdsAnchor.as_a(uint);
	};
    
    GenerateMACSecOnMacRootNode() is {
        gen RxMACSecHostType;
        gen SxMACSecHostType;
        gen RxMACSecMode;
        gen SxMACSecMode;
        gen RxSecTagSize;
        gen SxSecTagSize;
        gen RxSecTagMode;
        gen SxSecTagMode;
        if RxMACSecHostType != None {
            WithRxInlineAction = TRUE;
            WithRxModificationActions = FALSE;
        };
        if SxMACSecHostType != None {
            WithRxInlineAction = TRUE;
            WithSxModificationActions = FALSE;
        };
    };
    
};

extend FlowGenerator{

	//=================================================================================================================================================//
	//================================================= AUX & I/F Methods =============================================================================//
	//=================================================================================================================================================//

	GetNonEncapsulatedSmacs(Port : uint, Gvmi : uint(bits:16)) : list of uint(bits:48) is {
		for each in GetUnicastTree(Port,Gvmi).RootNode.Children.all(not it.SxSteeringModificationActions.SxModificationActionType.has(it in [Encapsulation,L3Encapsulation])) {
			result.add(it.FieldValue);
		};
	};

	IsEncapsulated(Smac : uint(bits:48)) : bool is {
		for each (Tree) in UnicastFlowsList {
			for each (Node) in Tree.GetAllChildren() {
				if Node.Kind in [Mac,MacByDecap] and Node.FieldValue == Smac and Node.SxSteeringModificationActions.SxModificationActionType.has(it == Encapsulation) {
					return TRUE;
				};
			};
		};
	};

	CanTakeQpnFromSteering(QpAllocation : QpAllocation) : bool is also{
		var SteeringNode : SteeringNode;
		var SteeringBranch : list of SteeringNode;
		for each (Tree) in UnicastFlowsList{
			SteeringBranch.add(Tree.GetAllChildren().all(it.Children.is_empty() and it.LevelInTree != 0 and
					it.QpAllocation != NULL and it.QpAllocation.ContextId == QpAllocation.ContextId and it.QpAllocation.Gvmi == QpAllocation.Gvmi));
		};
		if SteeringBranch.size() != 1{
			DUTError(62349,appendf("QpAllocation exists in more than 1 Branch"))
		}else{
			SteeringNode =  SteeringBranch[0];
		};
		return SteeringNode.FatherNode.Children.size() == 1;
	};

	GetBaseSteeringNode(SteeringEntry : SteeringEntry) : SteeringNode is{
		for each (Tree) in UnicastFlowsList{
			for each (Node) in Tree.GetAllChildren() {
				if (Node.Kind not in LookupTypeToFlowType(SteeringEntry.entry_sub_type.as_a(SteeringLookupType))) {
					continue;
				};
				case SteeringEntry.entry_sub_type.as_a(SteeringLookupType) {
					PortEthL2_1 : {
						if HANDLERS(Steering).GetSteeringLookupParamsDmac(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE) == Node.FieldValue {
							return Node;
						};
					};
					default : {
						DUTError(2712,appendf("unknown lu_type = %s",SteeringEntry.entry_sub_type.as_a(SteeringLookupType)));
					};
				};
			};
		};
	};

	BuildSteeringParamsFromPacket(SteeringParams : SteeringParams,Pkt : NetworkPacket) is also{
		if Pkt.HasHeader(IPv6) {
			SteeringParams.Ipv6DestAddress = Pkt.IPv6Header().DestGID;
			SteeringParams.Ipv6SrcAddress = Pkt.IPv6Header().SrcGID;
		};
		if Pkt.HasHeader(IPv4) {
			SteeringParams.Ipv4DestAddress = Pkt.IPv4Header().DestAddress;
			SteeringParams.Ipv4SrcAddress = Pkt.IPv4Header().SrcAddress;
		};
		if Pkt.HasHeader(TCP) {
			SteeringParams.DestPort = Pkt.TCPHeader().DestPort;
			SteeringParams.SourcePort = Pkt.TCPHeader().SrcPort;
		};
		if Pkt.HasHeader(UDP) {
			SteeringParams.DestPort = Pkt.UDPHeader().DestPort;
			SteeringParams.SourcePort = Pkt.UDPHeader().SrcPort;
		};
	};

	GetSteeringTypeString(SteeringLookupType,SteeringType,BasicSteeringTypeStringLen : uint) : SteeringType is {
		if SteeringLookupType in [DUMMY_STEERING_LOOKUP_TYPE] {
			var DummyExtensionString : string = str_sub(SteeringLookupType.as_a(string), BasicSteeringTypeStringLen+1, 7);
			result = appendf("%s%s",SteeringType,DummyExtensionString).as_a(SteeringType);
			return result;
		} else {
			return SteeringType;
		};
	};

	LookupTypeToFlowType(SteeringLookupType : SteeringLookupType) : list of SteeringType is{
		case SteeringLookupType {
			[PORT_ETHL2_1_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,Mac,11)}; };
			[MPLS_1_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,Mpls,6)}; };
			[VLAN_1_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,Vlan,6)}; };
			[ETHL3_IPV6DST_1_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,Ipv6Dst,14)}; };
			[ETHL3_IPV6SRC_1_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,Ipv6Src,14)}; };
			[ETHL4_1_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,Ipv6L4,7);GetSteeringTypeString(SteeringLookupType,L4Only,7)}; };
			[ETHL3_IPV45TUPLE_1_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,Ipv4_5Tuple,17)}; };
			[ETHL3_IPV4DST_1_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,Ipv4Dst,14)}; };
			[ETHL3_IPV4SRC_1_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,Ipv4Src,14)}; };
			[ESP_1_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,Esp,5)}; };
			[EthL2Tnl] : { return {TunnelType}; };
			[PORT_ETHL2_2_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,InnerMac,11)}; };
			[MPLS_2_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,InnerMpls,6)}; };
			[VLAN_2_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,InnerVlan,6)}; };
			[ETHL3_IPV6DST_2_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,InnerIpv6Dst,14)}; };
			[ETHL3_IPV6SRC_2_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,InnerIpv6Src,14)}; };
			[ETHL4_2_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,InnerIpv6L4,7);GetSteeringTypeString(SteeringLookupType,InnerL4Only,7)}; };
			[ETHL3_IPV45TUPLE_2_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,InnerIpv4_5Tuple,17)}; };
			[ETHL3_IPV4DST_2_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,InnerIpv4Dst,14)}; };
			[ETHL3_IPV4SRC_2_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,InnerIpv4Src,14)}; };
			[ESP_2_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,InnerEsp,5)}; };
			[PORT_ETHL2_BY_DECAP_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,MacByDecap,18)}; };
			[MPLS_BY_DECAP_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,MplsByDecap,13)}; };
			[VLAN_BY_DECAP_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,VlanByDecap,13)}; };
			[ETHL3_IPV6DST_BY_DECAP_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,Ipv6DstByDecap,21)}; };
			[ETHL3_IPV6SRC_BY_DECAP_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,Ipv6SrcByDecap,21)}; };
			[ETHL4_BY_DECAP_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,Ipv6L4ByDecap,14);GetSteeringTypeString(SteeringLookupType,L4OnlyByDecap,14)}; };
			[ETHL3_IPV45TUPLE_BY_DECAP_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,Ipv4_5TupleByDecap,24)}; };
			[ETHL3_IPV4DST_BY_DECAP_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,Ipv4DstByDecap,21)}; };
			[ETHL3_IPV4SRC_BY_DECAP_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,Ipv4SrcByDecap,21)}; };
			[ESP_BY_DECAP_LOOKUP_TYPE_WITH_DUMMY] : { return {GetSteeringTypeString(SteeringLookupType,EspByDecap,12)}; };
			[SteeringRegisters_0] : { return {Register0}; };
			[SteeringRegisters_1] : { return {Register1}; };
			[SteeringRegisters_2] : { return {Register2}; };
			[SteeringRegisters_3] : { return {Register3}; };
			[SteeringRegisters_4] : { return {Register4}; };
			[SteeringRegisters_5] : { return {Register5}; };

			[PortIbL2] : { return {Lid}; };
			[IbL3] : { return {Gid}; };
			[WredMask] : { return {WredMask}; };
			default : { DUTError(2562,appendf("Unknown SteeringLookupType %s",SteeringLookupType));};
		};
	};

	CalcRssHash(RssDataBase : RssDataBase,SteeringParams : SteeringParams):uint is also{
		var FirstPort : uint(bits:16);
		var SecondPort : uint(bits:16);
		var FirstIPv4Address : uint(bits:32);
		var SecondIPv4Address : uint(bits:32);
		var FirstIPv6Address : uint(bits:128);
		var SecondIPv6Address : uint(bits:128);
		var DestPort : uint(bits:16) = SteeringParams.DestPort;
		var SourcePort : uint(bits:16) = SteeringParams.SourcePort;
		var Ipv4DestAddress : uint(bits:32) = SteeringParams.Ipv4DestAddress;
		var Ipv4SrcAddress : uint(bits:32) = SteeringParams.Ipv4SrcAddress;
		var Ipv6DestAddress : uint(bits:128) = SteeringParams.Ipv6DestAddress;
		var Ipv6SrcAddress : uint(bits:128) = SteeringParams.Ipv6SrcAddress;

		if ((RssDataBase.RssL3Dst == Ipv4 or RssDataBase.RssL3Src == Ipv4) and (RssDataBase.RssL4Dst in [Tcp,Udp] or RssDataBase.RssL4Src in [Tcp,Udp])){
			var ToplitzInput : uint(bits:96);
			FirstPort = RssDataBase.RssL4Dst != None ? (RssDataBase.SymmetricTcpUdpAddress ? (DestPort ^ SourcePort) : DestPort) : 0;
			SecondPort = RssDataBase.RssL4Src != None ? (RssDataBase.SymmetricTcpUdpAddress ? (DestPort | SourcePort) : SourcePort) : 0;
			FirstIPv4Address = RssDataBase.RssL3Dst != None ? (RssDataBase.SymmetricIpAddress ? (Ipv4DestAddress ^ Ipv4SrcAddress) : Ipv4DestAddress) : 0;
			SecondIPv4Address = RssDataBase.RssL3Src != None ? (RssDataBase.SymmetricIpAddress ? (Ipv4DestAddress | Ipv4SrcAddress) : Ipv4SrcAddress) : 0;
			ToplitzInput[15:0] = FirstPort;
			ToplitzInput[31:16] = SecondPort;
			ToplitzInput[63:32] = FirstIPv4Address;
			ToplitzInput[95:64] = SecondIPv4Address;
			return ComputeToplitzHash(ToplitzInput,96,RssDataBase.RssKey);
		};
		if ((RssDataBase.RssL3Dst == Ipv4 or RssDataBase.RssL3Src == Ipv4) and (RssDataBase.RssL4Dst == None and RssDataBase.RssL4Src == None)) {
			var ToplitzInput : uint(bits:64);
			FirstIPv4Address = RssDataBase.RssL3Dst != None ? (RssDataBase.SymmetricIpAddress ? (Ipv4DestAddress ^ Ipv4SrcAddress) : Ipv4DestAddress) : 0;
			SecondIPv4Address = RssDataBase.RssL3Src != None ? (RssDataBase.SymmetricIpAddress ? (Ipv4DestAddress | Ipv4SrcAddress) : Ipv4SrcAddress) : 0;
			ToplitzInput[31:0] = FirstIPv4Address;
			ToplitzInput[63:32] = SecondIPv4Address;
			return ComputeToplitzHash(ToplitzInput,64,RssDataBase.RssKey);
		};
		if ((RssDataBase.RssL3Dst == Ipv6 or RssDataBase.RssL3Src == Ipv6) and (RssDataBase.RssL4Dst in [Tcp,Udp] or RssDataBase.RssL4Src in [Tcp,Udp])){
			var ToplitzInput : uint(bits:288);
			FirstPort = RssDataBase.RssL4Dst != None ? (RssDataBase.SymmetricTcpUdpAddress ? (DestPort ^ SourcePort) : DestPort) : 0;
			SecondPort = RssDataBase.RssL4Src != None ? (RssDataBase.SymmetricTcpUdpAddress ? (DestPort | SourcePort) : SourcePort) : 0;
			FirstIPv6Address = RssDataBase.RssL3Dst != None ? (RssDataBase.SymmetricIpAddress ? (Ipv6DestAddress ^ Ipv6SrcAddress) : Ipv6DestAddress) : 0;
			SecondIPv6Address = RssDataBase.RssL3Src != None ? (RssDataBase.SymmetricIpAddress ? (Ipv6DestAddress | Ipv6SrcAddress) : Ipv6SrcAddress) : 0;
			ToplitzInput[15:0] = FirstPort;
			ToplitzInput[31:16] = SecondPort;
			ToplitzInput[159:32] = FirstIPv6Address;
			ToplitzInput[287:160] = SecondIPv6Address;
			return ComputeToplitzHash(ToplitzInput,288,RssDataBase.RssKey);
		};
		if ((RssDataBase.RssL3Dst == Ipv6 or RssDataBase.RssL3Src == Ipv6) and (RssDataBase.RssL4Dst == None and RssDataBase.RssL4Src == None)){
			var ToplitzInput : uint(bits:256);
			FirstIPv6Address = RssDataBase.RssL3Dst != None ? (RssDataBase.SymmetricIpAddress ? (Ipv6DestAddress ^ Ipv6SrcAddress) : Ipv6DestAddress) : 0;
			SecondIPv6Address = RssDataBase.RssL3Src != None ? (RssDataBase.SymmetricIpAddress ? (Ipv6DestAddress | Ipv6SrcAddress) : Ipv6SrcAddress) : 0;
			ToplitzInput[127:0] = FirstIPv6Address;
			ToplitzInput[255:128] = SecondIPv6Address;
			return ComputeToplitzHash(ToplitzInput,256,RssDataBase.RssKey);
		};
		if ((RssDataBase.RssL3Dst == None and RssDataBase.RssL3Src == None) and (RssDataBase.RssL4Dst in [Tcp,Udp] or RssDataBase.RssL4Src in [Tcp,Udp])){
			var ToplitzInput : uint(bits:32);
			FirstPort = RssDataBase.RssL4Dst != None ? (RssDataBase.SymmetricTcpUdpAddress ? (DestPort ^ SourcePort) : DestPort) : 0;
			SecondPort = RssDataBase.RssL4Src != None ? (RssDataBase.SymmetricTcpUdpAddress ? (DestPort | SourcePort) : SourcePort) : 0;
			ToplitzInput[15:0] = FirstPort;
			ToplitzInput[31:16] = SecondPort;
			return ComputeToplitzHash(ToplitzInput,32,RssDataBase.RssKey);
		};
		if result != 0{
			DUTError(62582,appendf("Rss hash result = %s",result));
		};
	};

	ComputeToplitzHash(Input : uint(bits:288),SizeOfInput : uint,Key : uint(bits:320)) : uint is {
		result = 0;
		var TmpKey : uint;
		var KeyUpperIndex : uint = 319;
		for i from SizeOfInput-1 down to 0{
			TmpKey = Key[KeyUpperIndex:KeyUpperIndex - 31];
			if (Input[i:i] == 1){
				result ^= TmpKey;
			};
			KeyUpperIndex -= 1;
		};
	};

	GetAllNodesWithSpecificSonsType(SteeringType : SteeringType, MulticastNode : bool = FALSE) : list of SteeringNode is {
		if MulticastNode {
			for each (Tree) in MulticastFlowsList{
				for each (Node) in Tree.GetAllChildren(){
					if Node.Children.has(it.Kind == SteeringType and it.ValueType == CertainValue){
						result.add(Node);
					};
				};
			};
		} else {
			for each (Tree) in UnicastFlowsList{
				for each (Node) in Tree.GetAllChildren(){
					if Node.Children.has(it.Kind == SteeringType and it.ValueType == CertainValue){
						result.add(Node);
					};
				};
			};
		};
	};

	GetAllNodesWithSpecificType(SteeringType : SteeringType, MulticastNode : bool = FALSE) : list of SteeringNode is {
		if MulticastNode {
			for each (Tree) in MulticastFlowsList{
				for each (Node) in Tree.GetAllChildren(){
					if Node.Kind == SteeringType and Node.ValueType == CertainValue {
						result.add(Node);
					};
				};
			};
		} else {
			for each (Tree) in UnicastFlowsList{
				for each (Node) in Tree.GetAllChildren(){
					if Node.Kind == SteeringType and Node.ValueType == CertainValue {
						result.add(Node);
					};
				};
			};
		};
	};

	GetIBRootNode(DstLid : uint(bits:16),DstGid : uint(bits:128)) : SteeringNode is {
		for each (Tree) in UnicastFlowsList {
			for each (LidNode) in Tree.RootNode.Children.all(it.Kind == Lid) {
				if GvmiResolutionMode == LID {
					if LidNode.FieldValue[111:96] == (DstLid & (0xffff << LidNode.Lmc).as_a(uint(bits:16))) {
						return LidNode;
					};
				} else if GvmiResolutionMode == GID {
					for each (GidNode) in LidNode.Children.all(it.Kind == Gid) {
						if DstGid in GidNode.DGidList {
							return GidNode;
						};
					};
				};
			};
		};
	};

	GetRootNode(LocalFlow : bool, IsMac : bool,DLid : uint(bits:16),DGid : uint(bits:128),SLid : uint(bits:16),SGid : uint(bits:128),Mac : uint(bits:48),DstIp : uint(bits:128),SrcIp : uint(bits:128),Ipv64Not : bool = TRUE) : SteeringNode is{
		if IsMac{
			for each (Tree) in UnicastFlowsList{
				for each (MacNode) in Tree.RootNode.Children.all(it.RemoteFlow != LocalFlow and it.Kind in [Mac, MacByDecap]){
					if MacNode.FieldValue == Mac{
						return MacNode;
					};
				};
			};
		}else{
			for each (Tree) in UnicastFlowsList{
				if Tree.IBSteeringMode == IpoIbOnly and GvmiResolutionMode == LID and TOPOLOGY.GetClusterActiveLogicalPort(Tree.Port,External).LinkProtocol == IB {
					for each (LidNode) in Tree.RootNode.Children.all(it.RemoteFlow != LocalFlow and it.Kind == Lid){
						if (DLid & (0xffff << LidNode.Lmc).as_a(uint(bits:16))) == LidNode.FieldValue[111:96] or (SLid & (0xffff << LidNode.Lmc).as_a(uint(bits:16))) == LidNode.FieldValue[111:96] {
							for each (IpNode) in LidNode.Children.all(it.Kind in [Ipv6Dst,Ipv6Src,Ipv4_5Tuple,Ipv4Dst,Ipv4Src]){
								if ((Ipv64Not and IpNode.FieldValue == DstIp and IpNode.Kind == Ipv6Dst) or
										(Ipv64Not and IpNode.FieldValue == SrcIp and IpNode.Kind == Ipv6Src) or
										(!Ipv64Not and IpNode.Kind == Ipv4_5Tuple and IpNode.FieldValue[127:96] == DstIp and IpNode.FieldValue[95:64] == SrcIp) or
										(!Ipv64Not and IpNode.Kind == Ipv4Dst and IpNode.FieldValue == DstIp) or
										(!Ipv64Not and IpNode.Kind == Ipv4Src and IpNode.FieldValue == SrcIp)) {
									return IpNode;
								};
							};
						};
					};
				} else if Tree.IBSteeringMode == IpoIbOnly and GvmiResolutionMode == GID and TOPOLOGY.GetClusterActiveLogicalPort(Tree.Port,External).LinkProtocol == IB {
					for each (LidNode) in Tree.RootNode.Children.all(it.RemoteFlow != LocalFlow and it.Kind == Lid){
						if (DLid & (0xffff << LidNode.Lmc).as_a(uint(bits:16))) == LidNode.FieldValue[111:96] or (SLid & (0xffff << LidNode.Lmc).as_a(uint(bits:16))) == LidNode.FieldValue[111:96] {
							for each (GidNode) in LidNode.Children.all(it.Kind == Gid){
								if GidNode.DGidList.has(it == DGid) {//or it == SGid) {
									for each (IpNode) in GidNode.Children.all(it.Kind in [Ipv6Dst,Ipv6Src,Ipv4_5Tuple,Ipv4Dst,Ipv4Src]){
										if ((Ipv64Not and IpNode.FieldValue == DstIp and IpNode.Kind == Ipv6Dst) or
												(Ipv64Not and IpNode.FieldValue == SrcIp and IpNode.Kind == Ipv6Src) or
												(!Ipv64Not and IpNode.Kind == Ipv4_5Tuple and IpNode.FieldValue[127:96] == DstIp and IpNode.FieldValue[95:64] == SrcIp) or
												(!Ipv64Not and IpNode.Kind == Ipv4Dst and IpNode.FieldValue == DstIp) or
												(!Ipv64Not and IpNode.Kind == Ipv4Src and IpNode.FieldValue == SrcIp)) {
											return IpNode;
										};
									};
								};
							};
						};
					};
				} else {
					for each (IpNode) in Tree.RootNode.Children.all(it.RemoteFlow != LocalFlow and it.Kind in [Ipv6Dst,Ipv6Src,Ipv4_5Tuple,Ipv4Dst,Ipv4Src]){
						if ((Ipv64Not and IpNode.FieldValue == DstIp and IpNode.Kind == Ipv6Dst) or
								(Ipv64Not and IpNode.FieldValue == SrcIp and IpNode.Kind == Ipv6Src) or
								(!Ipv64Not and IpNode.Kind == Ipv4_5Tuple and IpNode.FieldValue[127:96] == DstIp and IpNode.FieldValue[95:64] == SrcIp) or
								(!Ipv64Not and IpNode.Kind == Ipv4Dst and IpNode.FieldValue == DstIp) or
								(!Ipv64Not and IpNode.Kind == Ipv4Src and IpNode.FieldValue == SrcIp)) {
							return IpNode;
						};
					};
				};
			};
		};
	};

	//=================================================================================================================================================//
	//================================================= ReWriteAction ================================================================================//
	//=================================================================================================================================================//

	UpdateReWriteActionsOnFieldValue(SteeringNode) : uint (bits:128) is {
		var UpdatedFieldValue : uint (bits:128) = SteeringNode.FieldValue;
		if SteeringNode.ParentNodes.has(it.SteeringNodeHasRewriteActions(RX)) {
		};
		return UpdatedFieldValue;
	};

	GetSteeringNodeWithSameParameters(SteeringEntry : SteeringEntry) : SteeringNode is{
		var SteeringTree : SteeringTree;
		if SteeringEntry.MulticastEntry {
			SteeringTree = GetMulticastTree(SteeringEntry.SteeringLookupParams.Port,SteeringEntry.IsLeafEntry ? SteeringEntry.ParentSteeringSuperTable.SteeringTable.Gvmi : SteeringEntry.SteeringLookupParams.Gvmi);
		} else {
			SteeringTree = GetUnicastTree(SteeringEntry.SteeringLookupParams.Port,SteeringEntry.SteeringLookupParams.Gvmi);
		};
		for each (Node) in SteeringTree.GetAllChildren(){
			if (Node.ValueType == CertainValue and (Node.Kind in LookupTypeToFlowType(SteeringEntry.entry_sub_type.as_a(SteeringLookupType)) or Node.Kind == Vlan)){
				var ReWritedFieldValue : uint (bits:128) = UpdateReWriteActionsOnFieldValue(Node);
				case Node.Kind{
					[MAC_STEERING_TYPE_WITH_DUMMY] : {
						if (ReWritedFieldValue == HANDLERS(Steering).GetSteeringLookupParamsDmac(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE) and
								HANDLERS(Steering).GetSteeringLookupParamsVlanQualifier(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE,FALSE) == NoVlan and
								HANDLERS(Steering).GetSteeringLookupParamsVlanQualifier(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,TRUE,FALSE) == NoVlan) {
							return Node;
						};
					};
					[MAC_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
						if (ReWritedFieldValue == HANDLERS(Steering).GetSteeringLookupParamsDmac(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,SteeringEntry.RxSx == SX ? TRUE : FALSE) and
								HANDLERS(Steering).GetSteeringLookupParamsVlanQualifier(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE,SteeringEntry.RxSx == SX ? TRUE : FALSE) == NoVlan and
								HANDLERS(Steering).GetSteeringLookupParamsVlanQualifier(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,TRUE,SteeringEntry.RxSx == SX ? TRUE : FALSE) == NoVlan){
							return Node;
						};
					};
					[INNER_MAC_STEERING_TYPE_WITH_DUMMY] : {
						if (ReWritedFieldValue == HANDLERS(Steering).GetSteeringLookupParamsDmac(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,TRUE) and
								HANDLERS(Steering).GetSteeringLookupParamsVlanQualifier(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE,TRUE) == NoVlan and
								HANDLERS(Steering).GetSteeringLookupParamsVlanQualifier(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,TRUE,TRUE) == NoVlan){
							return Node;
						};
					};
					[WredMask] : {
						if Node.WredBuffersMask == HANDLERS(Steering).GetSteeringLookupParamsWred(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE) and
							Node.FieldValue == HANDLERS(Steering).GetSteeringLookupParamsDmac(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE) {
							return Node;
						};
					};
					[VLAN_STEERING_TYPE_WITH_DUMMY,INNER_VLAN_STEERING_TYPE_WITH_DUMMY,VLAN_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
						if SteeringEntry.entry_sub_type.as_a(SteeringLookupType) in [PORT_ETHL2_1_LOOKUP_TYPE_WITH_DUMMY,PORT_ETHL2_2_LOOKUP_TYPE_WITH_DUMMY,PORT_ETHL2_BY_DECAP_LOOKUP_TYPE_WITH_DUMMY,
								VLAN_1_LOOKUP_TYPE_WITH_DUMMY,VLAN_2_LOOKUP_TYPE_WITH_DUMMY,VLAN_BY_DECAP_LOOKUP_TYPE_WITH_DUMMY]{
							var MacInternalHeader : list of MacInternalHeader;
							MacInternalHeader.add(BuildMacInternalHeaderFromSteeringEntry(SteeringEntry,Node.Kind in [INNER_VLAN_STEERING_TYPE_WITH_DUMMY] or (SteeringEntry.RxSx == SX and Node.Kind in [VLAN_BY_DECAP_STEERING_TYPE_WITH_DUMMY])));
							if VlansMatch(MacInternalHeader,Node.VlanList,TRUE){
								if SteeringEntry.entry_sub_type.as_a(SteeringLookupType) in [PORT_ETHL2_1_LOOKUP_TYPE_WITH_DUMMY,PORT_ETHL2_2_LOOKUP_TYPE_WITH_DUMMY,PORT_ETHL2_BY_DECAP_LOOKUP_TYPE_WITH_DUMMY] {
									return Node.ParentNodes.first(it.Kind == Mac);
								} else {
									return Node;
								};
							};
						};
					};
					[MPLS_STEERING_TYPE_WITH_DUMMY,INNER_MPLS_STEERING_TYPE_WITH_DUMMY,MPLS_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
						if SteeringEntry.entry_sub_type.as_a(SteeringLookupType) in [MPLS_1_LOOKUP_TYPE_WITH_DUMMY,MPLS_2_LOOKUP_TYPE_WITH_DUMMY,MPLS_BY_DECAP_LOOKUP_TYPE_WITH_DUMMY] {
							var MplsLabels : list of MPLSLabelStack;
							MplsLabels.add(BuildMplsLabelFromSteeringEntry(SteeringEntry,Node.Kind in [INNER_MPLS_STEERING_TYPE_WITH_DUMMY] or (SteeringEntry.RxSx == SX and Node.Kind in [MPLS_BY_DECAP_STEERING_TYPE_WITH_DUMMY])));
							if MplsLabelsMatch(MplsLabels,Node.MplsLabelHeader.MPLSLabelStackList,TRUE){
								if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
									return Node;
								};
							};
						};
					};
					[ESP_STEERING_TYPE_WITH_DUMMY,INNER_ESP_STEERING_TYPE_WITH_DUMMY,ESP_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
						if ReWritedFieldValue == HANDLERS(Steering).GetBasicSteeringDefinerFieldValue(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,IPSec_SPI) {
							if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
								return Node;
							};
						};
					};
					[IPV6DST_STEERING_TYPE_WITH_DUMMY] : {
						if ReWritedFieldValue == HANDLERS(Steering).GetSteeringLookupParamsIPv6DestAddress(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE) {
							if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
								return Node;
							};
						};
					};
					[IPV6DST_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
						if ReWritedFieldValue == HANDLERS(Steering).GetSteeringLookupParamsIPv6DestAddress(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,SteeringEntry.RxSx == SX ? TRUE : FALSE) {
							if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
								return Node;
							};
						};
					};
					[INNER_IPV6DST_STEERING_TYPE_WITH_DUMMY] : {
						if ReWritedFieldValue == HANDLERS(Steering).GetSteeringLookupParamsIPv6DestAddress(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,TRUE) {
							if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
								return Node;
							};
						};
					};
					[IPV6SRC_STEERING_TYPE_WITH_DUMMY] : {
						if ReWritedFieldValue == HANDLERS(Steering).GetSteeringLookupParamsIPv6SrcAddress(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE) {
							if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
								return Node;
							};
						};
					};
					[IPV6SRC_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
						if ReWritedFieldValue == HANDLERS(Steering).GetSteeringLookupParamsIPv6SrcAddress(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,SteeringEntry.RxSx == SX ? TRUE : FALSE) {
							if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
								return Node;
							};
						};
					};
					[INNER_IPV6SRC_STEERING_TYPE_WITH_DUMMY] : {
						if ReWritedFieldValue == HANDLERS(Steering).GetSteeringLookupParamsIPv6SrcAddress(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,TRUE) {
							if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
								return Node;
							};
						};
					};
					[IPV4DST_STEERING_TYPE_WITH_DUMMY] : {
						if ReWritedFieldValue == HANDLERS(Steering).GetSteeringLookupParamsIPv4DestAddress(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE) {
							if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
								return Node;
							};
						};
					};
					[IPV4DST_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
						if ReWritedFieldValue == HANDLERS(Steering).GetSteeringLookupParamsIPv4DestAddress(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,SteeringEntry.RxSx == SX ? TRUE : FALSE) {
							if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
								return Node;
							};
						};
					};
					[INNER_IPV4DST_STEERING_TYPE_WITH_DUMMY] : {
						if ReWritedFieldValue == HANDLERS(Steering).GetSteeringLookupParamsIPv4DestAddress(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,TRUE) {
							if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
								return Node;
							};
						};
					};
					[IPV4SRC_STEERING_TYPE_WITH_DUMMY] : {
						if ReWritedFieldValue == HANDLERS(Steering).GetSteeringLookupParamsIPv4SrcAddress(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE) {
							if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
								return Node;
							};
						};
					};
					[IPV4SRC_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
						if ReWritedFieldValue == HANDLERS(Steering).GetSteeringLookupParamsIPv4SrcAddress(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,SteeringEntry.RxSx == SX ? TRUE : FALSE) {
							if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
								return Node;
							};
						};
					};
					[INNER_IPV4SRC_STEERING_TYPE_WITH_DUMMY] : {
						if ReWritedFieldValue == HANDLERS(Steering).GetSteeringLookupParamsIPv4SrcAddress(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,TRUE) {
							if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
								return Node;
							};
						};
					};
					[IPV45TUPLE_STEERING_TYPE_WITH_DUMMY] : {
						if (ReWritedFieldValue[127:96] == HANDLERS(Steering).GetSteeringLookupParamsIPv4DestAddress(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE) and
								ReWritedFieldValue[95:64]  == HANDLERS(Steering).GetSteeringLookupParamsIPv4SrcAddress(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE) and
								ReWritedFieldValue[63:48]  == HANDLERS(Steering).GetSteeringLookupParamsSrcPort(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE) and
								ReWritedFieldValue[47:32]  == HANDLERS(Steering).GetSteeringLookupParamsDestPort(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE)) {
							if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
								return Node;
							};
						};
					};
					[IPV45TUPLE_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
						if (ReWritedFieldValue[127:96] == HANDLERS(Steering).GetSteeringLookupParamsIPv4DestAddress(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,SteeringEntry.RxSx == SX ? TRUE : FALSE) and
								ReWritedFieldValue[95:64]  == HANDLERS(Steering).GetSteeringLookupParamsIPv4SrcAddress(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,SteeringEntry.RxSx == SX ? TRUE : FALSE) and
								ReWritedFieldValue[63:48]  == HANDLERS(Steering).GetSteeringLookupParamsSrcPort(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,SteeringEntry.RxSx == SX ? TRUE : FALSE) and
								ReWritedFieldValue[47:32]  == HANDLERS(Steering).GetSteeringLookupParamsDestPort(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,SteeringEntry.RxSx == SX ? TRUE : FALSE)) {
							if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
								return Node;
							};
						};
					};
					[INNER_IPV45TUPLE_STEERING_TYPE_WITH_DUMMY] : {
						if (ReWritedFieldValue[127:96] == HANDLERS(Steering).GetSteeringLookupParamsIPv4DestAddress(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,TRUE) and
								ReWritedFieldValue[95:64]  == HANDLERS(Steering).GetSteeringLookupParamsIPv4SrcAddress(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,TRUE) and
								ReWritedFieldValue[63:48]  == HANDLERS(Steering).GetSteeringLookupParamsSrcPort(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,TRUE) and
								ReWritedFieldValue[47:32]  == HANDLERS(Steering).GetSteeringLookupParamsDestPort(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,TRUE)) {
							if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
								return Node;
							};
						};
					};
					[IPV6L4_STEERING_TYPE_WITH_DUMMY,L4ONLY_STEERING_TYPE_WITH_DUMMY] : {
						if (ReWritedFieldValue[111:96] == HANDLERS(Steering).GetSteeringLookupParamsDestPort(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE) and
								ReWritedFieldValue[79:64]  == HANDLERS(Steering).GetSteeringLookupParamsSrcPort(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,FALSE)) {
							if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
								return Node;
							};
						};
					};
					[IPV6L4_BY_DECAP_STEERING_TYPE_WITH_DUMMY,L4ONLY_BY_DECAP_STEERING_TYPE_WITH_DUMMY] : {
						if (ReWritedFieldValue[111:96] == HANDLERS(Steering).GetSteeringLookupParamsDestPort(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,SteeringEntry.RxSx == SX ? TRUE : FALSE) and
								ReWritedFieldValue[79:64]  == HANDLERS(Steering).GetSteeringLookupParamsSrcPort(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,SteeringEntry.RxSx == SX ? TRUE : FALSE)) {
							if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
								return Node;
							};
						};
					};
					[INNER_IPV6L4_STEERING_TYPE_WITH_DUMMY,INNER_L4ONLY_STEERING_TYPE_WITH_DUMMY] : {
						if (ReWritedFieldValue[111:96] == HANDLERS(Steering).GetSteeringLookupParamsDestPort(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,TRUE) and
								ReWritedFieldValue[79:64]  == HANDLERS(Steering).GetSteeringLookupParamsSrcPort(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList,TRUE)) {
							if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
								return Node;
							};
						};
					};
					TunnelType : {
						if Node.SteeringTunnelType == GRE {
							if ReWritedFieldValue[63:32] == HANDLERS(Steering).GetSteeringLookupParamsTunnelHeader2(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList) {
								if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
									return Node;
								};
							};
						} else if Node.SteeringTunnelType in [NVGRE,VXLAN] {
							if ReWritedFieldValue[63:32] == HANDLERS(Steering).GetSteeringLookupParamsTunnelHeader1(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList) {
								if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
									return Node;
								};
							};
						};
					};
					[STEERING_REGISTER_TYPES] : {
						if SteeringEntry.EntryNodeValueForMatch == Node.EntryNodeValueForMatch {
							return Node;
						};
					};
					Gid : {
						if Node.FieldValue == HANDLERS(Steering).GetSteeringLookupParamsIPv6SrcAddress(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList) {
							return Node;
						};
					};
					Lid : {
						if (Node.FieldValue[111:96] == (HANDLERS(Steering).GetSteeringLookupParamsDlid(SteeringEntry.SteeringLookupParams.SteeringDefiner.SteeringDefinerFieldList) & (0xffff << SteeringEntry.SteeringLookupParams.Lmc).as_a(uint(bits:16)))) {
							return Node;
						};
					};
				};
			};
		};
	};

	GetSteeringNodeByIndex(Index : uint) : SteeringNode is{
		for each (Tree) in  {UnicastFlowsList;MulticastFlowsList} {
			for each (Node) in Tree.GetAllChildren(){
				if Node.NodeIndex == Index{
					return Node;
				};
			};
		};
	};

	//=================================================================================================================================================//
	//================================================= Encapsulation ================================================================================//
	//=================================================================================================================================================//

	BuildEncapsulatingPacketRequirements(SteeringNode,SxModificationActionType : SteeringNodeActionType,RoceOverVxlanNode : SteeringNode = NULL): NetworkPacketRequirements is {
		var IPSecTunneled : bool = SteeringNode.SxIPSecHostType == Unaware and SteeringNode.SxIPSecMode in [Tunneled_IPv4,Tunneled_IPv6];
		result = new;
		result.AddToList(L2Kinds);
		result.L2Kinds = {MAC};
		result.AddToList(GREHasCS);
		result.GREHasCS = FALSE;
		result.AddToList(MinTunnelingDepth);
		result.MinTunnelingDepth = 1;
		result.AddToList(MaxTunnelingDepth);
		result.MaxTunnelingDepth = 1;
		result.AddToList(DoNotGenerateRandomPayload);
		result.AddToList(MaxHeadersSize);
		result.MaxHeadersSize = MAX_ENCAP_HEADERS_SIZE;
		result.PBRequirements = new;
		result.AddToList(PBRequirements);
        for each (Kind) in all_values(NetworkProtocol) {
            for each (Kind) in all_values(NetworkProtocol) {
                NetworkPacketGenerator.AddEndOffset2PB(result.PBRequirements,{Kind},result.MaxHeadersSize);
            };
        };
        //result.AddToList(MaxSize);
		if SteeringNode.SxIPSecHostType != Unaware {
			result.AddToList(NotAllowedKinds);
			result.NotAllowedKinds.add(ESP);
		};
		//result.MaxSize = result.MaxHeadersSize + 0x40;
		if RoceOverVxlanNode != NULL or IPSecTunneled {
			if (RoceOverVxlanNode != NULL and RoceOverVxlanNode.ParentNodes.has(it.Kind == Vlan)) or (IPSecTunneled and SteeringNode.ParentNodes.has(it.Kind == Vlan)) {
				var VlanList : list of MacInternalHeader = IPSecTunneled ? SteeringNode.ParentNodes.first(it.Kind == Vlan).VlanList : RoceOverVxlanNode.ParentNodes.first(it.Kind == Vlan).VlanList;
				for each (Vlan) in VlanList {
					result.AddToList(MacInternalHeaderTypes);
					result.MacInternalHeaderTypes.add(Vlan.EtherType == CVLAN_ETHERTYPE_SPEC ? CVlan : SVlan);
				};
			};
			if (RoceOverVxlanNode != NULL and RoceOverVxlanNode.ParentNodes.has(it.Kind == Mpls)) or (IPSecTunneled and SteeringNode.ParentNodes.has(it.Kind == Mpls)) {
				var MPLSLabelStackList : list of MPLSLabelStack = IPSecTunneled ? SteeringNode.ParentNodes.first(it.Kind == Mpls).MplsLabelHeader.MPLSLabelStackList : RoceOverVxlanNode.ParentNodes.first(it.Kind == Mpls).MplsLabelHeader.MPLSLabelStackList;
				result.AddToList(DoAddMplsHeader);
				result.AddToList(NumOfMplsLabels);
				if MPLSLabelStackList.last(TRUE).BottomOfStack == 1 {
					result.NumOfMplsLabels = MPLSLabelStackList.size();
				} else {
					result.NumOfMplsLabels = MPLSLabelStackList.size() + 1;
				};
			} else {
				if not result.HasRequirement(PBRequirements) {
					result.PBRequirements = new;
					result.AddToList(PBRequirements);
				};
				result.PBRequirements.AddToList(NotAllowedHeaderKinds);
				result.PBRequirements.NotAllowedHeaderKinds.add(MPLS);
			};
			if IPSecTunneled {
                if not result.HasRequirement(PBRequirements) {
                    result.PBRequirements = new;
                    result.AddToList(PBRequirements);
                };
                if SteeringNode.SxIPSecMode == Tunneled_IPv4 {
					result.AddToList(L3Kinds);
					result.L3Kinds = {IPv4};
				} else if SteeringNode.SxIPSecMode == Tunneled_IPv6 {
					result.AddToList(L3Kinds);
					result.L3Kinds = {IPv6};
				};
				if SteeringNode.SxEspMode == OverUdp {
					result.AddToList(L4Kinds);
					result.L4Kinds = {UDP};
					var UDPNextHeader : AdjacentHeaders = new with {
						.HeaderKind = UDP;
						.WantedHeaders = TRUE;
						.NextHeaders = {ESP};
					};
					result.PBRequirements.AddToList(AdjacentHeaders);
					result.PBRequirements.AdjacentHeaders.add(UDPNextHeader);
				} else {
					result.PBRequirements.AddToList(NotAllowedHeaderKinds);
					result.PBRequirements.NotAllowedHeaderKinds.add(UDP);
				};
				result.AddToList(TunnelType);
				result.TunnelType = ESP;
				result.PBRequirements.AddToList(HeadersReq);
				var HeaderReq: HeaderRequirements = NetworkPacketGenerator.GetHeadersReq(result.PBRequirements,ESP);
				HeaderReq.AddToList(AuthDataSize);
				HeaderReq.as_a(ESP HeaderRequirements).AuthDataSize = (SteeringNode.IPSecAuthenticationTagLength == Byte16) ? 16 : ((SteeringNode.IPSecAuthenticationTagLength == Byte12) ? 12 : 8);
				HeaderReq = NetworkPacketGenerator.GetHeadersReq(result.PBRequirements,IPv6);
				HeaderReq.AddToList(NotAllowedIPv6Options);
				HeaderReq.as_a(IPV6_HEADER_REQ).NotAllowedIPv6Options.add(all_values(IPv6ExtensionType));

			} else {
				if RoceOverVxlanNode.ParentNodes.has(it.Kind in [Ipv4_5Tuple,Ipv4_5TupleByDecap,Ipv6Dst,Ipv6DstByDecap,Ipv6L4,Ipv6L4ByDecap,Ipv6Src,Ipv6SrcByDecap]) {
					result.AddToList(L3Kinds);
					if RoceOverVxlanNode.ParentNodes.has(it.Kind in [Ipv4_5Tuple,Ipv4_5TupleByDecap]) {
						result.L3Kinds = {IPv4};
					} else {
						result.L3Kinds = {IPv6};
					};
				};
				result.AddToList(TunnelType);
				result.TunnelType = VXLAN;
			};
		} else {
			result.AddToList(L3Kinds);
			result.L3Kinds = {IPv6;IPv4};
			result.AddToList(NotAllowedTunnelTypes);
			result.NotAllowedTunnelTypes.add(FlexParsing);
			if SxModificationActionType == L3Encapsulation {
				result.NotAllowedTunnelTypes.add({GenericEncap;VXLAN}); // in L3Encapsulation allowed only GRE
			};
			if not EnableGenericEncapInEncapsulatedPacket and GenericEncap not in result.NotAllowedTunnelTypes{
				result.NotAllowedTunnelTypes.add(GenericEncap);
			};
			if {SteeringNode;SteeringNode.ParentNodes}.Kind.has(it == Vlan) {
				result.AddToList(MacInternalHeaderTypes);
				result.MacInternalHeaderTypes.add(CVlan);
			};
			if {SteeringNode;SteeringNode.ParentNodes}.Kind.has(it in [ALL_IPV6DST_STEERING_TYPE_WITH_DUMMY,ALL_IPV6SRC_STEERING_TYPE_WITH_DUMMY, ALL_IPV6L4_STEERING_TYPE_WITH_DUMMY]) {
				result.L3Kinds={IPv6};
			};

			if {SteeringNode;SteeringNode.ParentNodes}.Kind.has(it in [ALL_IPV4DST_STEERING_TYPE_WITH_DUMMY,ALL_IPV4SRC_STEERING_TYPE_WITH_DUMMY,ALL_IPV45TUPLE_STEERING_TYPE_WITH_DUMMY]) {
				result.L3Kinds={IPv4};
			};
		};
		result.AddToList(DoNotAddConfigurables);
		if HANDLERS(Config).GetLogicalPortConfigInfoList().key(SteeringNode.SteeringTree.Port).PrioInfo.SxPrioSourceType == MplsExpDscpDefault { //approved by Adi. sx parser can identify the mpls when we have vlans, but ports are not.
			result.AddToList(DoNotAddExtraMacInternalHeaders);
		};
		result.AddToList(MacHasLLCSNAP);
		result.MacHasLLCSNAP = FALSE;
		//inner
		result.InnerRequirements = new;
		if SxModificationActionType == L3Encapsulation  {
			result.AddToList(NotAllowedGreTypes);
			result.NotAllowedGreTypes = {NVGRE};
			result.InnerRequirements.AddToList(FirstLayer);
			result.InnerRequirements.FirstLayer = 3;
			result.InnerRequirements.AddToList(L3Kinds);
			result.InnerRequirements.L3Kinds = {SteeringNode.Kind;SteeringNode.ParentNodes.Kind}.has(it in [Ipv4Dst,Ipv4Src,Ipv4_5Tuple,L4Only]) ? {IPv4} : {IPv6};
		} else if SxModificationActionType == Encapsulation or RoceOverVxlanNode != NULL {
			result.InnerRequirements.AddToList(L2Kinds);
			result.InnerRequirements.L2Kinds = {MAC};
		};
		if not result.HasRequirement(PBRequirements) {
			result.PBRequirements = new;
			result.AddToList(PBRequirements);
		};
		result.PBRequirements.AddToList(GranularityOfHeaders);
		result.PBRequirements.GranularityOfHeaders = 1;
		NetworkPacketGenerator.AddEndOffset2PB(result.PBRequirements,{Other},result.MaxHeadersSize);
		NetworkPacketGenerator.AddNoIpFragmentToPacketBuilderRequirements(result.PBRequirements);
		messagef(HIGH,"BuildEncapsulatingPacketRequirements - Added requirements for no ip fragment");
	};

	CreateEncapsulatePacket(SteeringNode,SxModificationActionType : SteeringNodeActionType,RoceOverVxlanNode : SteeringNode = NULL) is also {
		var NetworkPacketRequirements : NetworkPacketRequirements = BuildEncapsulatingPacketRequirements(SteeringNode,SxModificationActionType,RoceOverVxlanNode);
		var Packet : NetworkPacket = NetworkPacketGenerator.GenPacket(NetworkPacketRequirements);
        if Packet.Headers.last(TRUE).HeaderOffset + Packet.Headers.last(TRUE).HeaderSize(FALSE) > MAX_ENCAP_HEADERS_SIZE {
            DUTError(6156,"Encap Packet headers size is great than 0x%x",MAX_ENCAP_HEADERS_SIZE) {
                Packet.PrintMe();
            };
        };
		var IPSecTunneled : bool = SteeringNode.SxIPSecHostType == Unaware and SteeringNode.SxIPSecMode in [Tunneled_IPv4,Tunneled_IPv6];
		if Packet.TunnelType==VXLAN or SteeringNode.SxEspMode == OverUdp {
			Packet.UDPHeader().Checksum = 0;
			Packet.UDPHeader().CalculatedChecksumAlready=TRUE;
		};
		if RoceOverVxlanNode != NULL or IPSecTunneled {
			UpdateRoceOverVxlanPacketFields(Packet,IPSecTunneled ? SteeringNode : RoceOverVxlanNode, IPSecTunneled);
		};
		if IPSecTunneled  and SteeringNode.SxEspMode == OverUdp and SteeringNode.ParentNodes.has(it.Kind in [L4Only,Ipv6L4]) and SteeringNode.ParentNodes.first(it.Kind in [L4Only,Ipv6L4]).L4Type == TCP {
			Packet.UDPHeader().SrcPort = SteeringNode.ParentNodes.first(it.Kind in [L4Only,Ipv6L4]).FieldValue[79:64];
			if SteeringNode.ParentNodes.first(it.Kind in [L4Only,Ipv6L4]).FieldValue[111:96] in HANDLERS(Config).NetworkPacketConfig.ESP_PORTList {
				Packet.UDPHeader().DestPort = SteeringNode.ParentNodes.first(it.Kind in [L4Only,Ipv6L4]).FieldValue[111:96];
			} else {
				SteeringNode.ParentNodes.first(it.Kind in [L4Only,Ipv6L4]).FieldValue[111:96] = Packet.UDPHeader().DestPort;
			};
		};
		messagef(HIGH, "Generated encapsulating packet: outer headers size = %s \n", Packet.HeadersSize(FALSE)) {
			Packet.PrintMe();
			outf("Packed packet: \n");
			print Packet.Pack(FALSE)[0..Packet.HeadersSize(FALSE)-1];
		};
		Packet.MACHeader().SourceAddr[40:40] = 0; //ensure no multicast
		if NeedToChangePacketPrio(SteeringNode, Packet) {
			var EncapPrio : uint(bits:3) = HANDLERS(Config).GetLogicalPortConfigInfoList().key(SteeringNode.SteeringTree.Port).PrioInfo.DefaultPrio;
			var Direction : NetworkPacketDirection = SteeringNode.RemoteFlow ? Outbound : Inbound;
			var PrioSourceType : PrioSourceType;
			if Direction == Inbound {
				PrioSourceType = HANDLERS(Config).GetLogicalPortConfigInfoList().key(SteeringNode.SteeringTree.Port).PrioInfo.RxPrioSourceType;
			} else {
				PrioSourceType = HANDLERS(Config).GetLogicalPortConfigInfoList().key(SteeringNode.SteeringTree.Port).PrioInfo.SxPrioSourceType
			};
			if {SteeringNode.ParentNodes;SteeringNode}.Kind.has(it in [Vlan] and PrioSourceType in [VlanDefault]) {
				EncapPrio = {SteeringNode.ParentNodes;SteeringNode}.first(it.Kind in [Vlan]).VlanList[0].PCP;
			};
			if PrioSourceType in [DscpDefault, MplsExpDscpDefault, MplsExpDscpVlanDefault, VlanMplsExpDscpDefault, VlanDefault] {
				var ConfigRequirements : ConfigRequirements = new with {
					it.PortNum = SteeringNode.SteeringTree.Port;
				};
				var Tclass : uint(bits:8);
				gen Tclass keeping {
					it[7:2] in HANDLERS(Config).Prio2Dscp(ConfigRequirements, EncapPrio);
				};
				if Packet.HasHeader(IPv4) {
					Packet.IPv4Header().TypeOfService = Tclass;
				} else if Packet.HasHeader(IPv6) {
					Packet.IPv6Header().TClass = Tclass;
				};
				if PrioSourceType in [MplsExpDscpDefault, MplsExpDscpVlanDefault, VlanMplsExpDscpDefault] {
					if Packet.HasHeader(MPLS) and not {SteeringNode;SteeringNode.ParentNodes}.has(it.Kind == Mpls) {
						var MplsTrafficClass : uint(bits:3);
						gen MplsTrafficClass keeping {
							it in HANDLERS(Config).Prio2Mpls(ConfigRequirements, EncapPrio);
						};
						Packet.MPLSHeader().MPLSLabelStackList[0].TrafficClass = MplsTrafficClass;
					};
				};
				if PrioSourceType in [VlanDefault] {
					if not Packet.MACHeader().MacInternalHeaders.is_empty() {
						Packet.MACHeader().MacInternalHeaders[0].PCP = EncapPrio;
					};
				};
			};
		};
		if RoceOverVxlanNode == NULL and not IPSecTunneled {
			Packet.MACHeader().DestAddr[40:40] = 0; //ensure no multicast
			if DMacGenerator.OldNums.has(it == Packet.MACHeader().DestAddr) {
				Packet.MACHeader().DestAddr = DMacGenerator.GenNum();
				DMacGenerator.OldNums.add(Packet.MACHeader().DestAddr);
				if Packet.MACHeader().DestAddr[40:40] != 0 {
					Packet.MACHeader().DestAddr[40:40] = 0; //ensure no multicast
					DMacGenerator.OldNums.add(Packet.MACHeader().DestAddr);
				}else{
					var TmpMac : uint(bits:48) = Packet.MACHeader().DestAddr;
					TmpMac[40:40] = 1;
					HANDLERS(LocalQp).FlowGenerator.DMacGenerator.OldNums.add(TmpMac);
				};
			} else {
				DMacGenerator.OldNums.add(Packet.MACHeader().DestAddr);
				var TmpMac : uint(bits:48) = Packet.MACHeader().DestAddr;
				TmpMac[40:40] = 1;
				DMacGenerator.OldNums.add(TmpMac);
			};
		};
		if GetPossibleMacForOverlay(SteeringNode) != None {
			Packet.MACHeader().DestAddr = SteeringNode.LoopbackDmac;
		};
		var SizeOfEncapsulatedEntry : uint = Packet.HeadersSize(FALSE);
		if SizeOfEncapsulatedEntry%2!=0 {
			DUTError(8763, "Generated encapsulating packet but size is not word aligned (%s)", SizeOfEncapsulatedEntry);
		};
		if SteeringNode.SxSteeringModificationActions.SxModificationActionType.has(it in [Encapsulation]) {
			var EncapsulatedPacketWithSmac : EncapsulatedPacketWithSmac = new with{
				.Packet = deep_copy(Packet);
				.Smac = SteeringNode.FieldValue;
			};
			EncapsulatedPacketList.add(EncapsulatedPacketWithSmac);
		};
		var PacketByteList : list of byte = Packet.Pack(FALSE)[0..SizeOfEncapsulatedEntry-1];
		SteeringNode.EncapsulationDataBase = new;
		SteeringNode.EncapsulationDataBase.EncapsulatedSteeringEntry = deep_copy(PacketByteList);
		SteeringNode.EncapsulationDataBase.PacketByteList = deep_copy(PacketByteList);
		SteeringNode.EncapsulationDataBase.Packet = deep_copy(Packet);
	};

	GetEncapsulatedPacketBySmac(Smac : uint(bits:48)) : NetworkPacket is also{
		return EncapsulatedPacketList.first(it.Smac == Smac).Packet;
	};

	GetPossibleMacForOverlay(SteeringNode) : EncapsulationLoopbackType is {
		SteeringNode.SmacEncapsulationLoopbackType = None;
		var EndMacNodeList : list of SteeringNode = {};
		for each (Tree) in HANDLERS(LocalQp).FlowGenerator.UnicastFlowsList {
			EndMacNodeList.add(Tree.GetAllChildren().all(it.Kind == Mac and (it.IsRoce or it.RoCE) and it.RssMode == RssGroup and it.Children.is_empty()));
		};
		if not EndMacNodeList.is_empty() {
			var OuterDMacNode : SteeringNode = EndMacNodeList.RANDOM_ITEM();
			OuterDMacNode.DmacEncapsulationLoopbackType = OuterDMacNode.IsRoce or OuterDMacNode.RoCE ? LoopbackRoceOverlay : RegularLoopback;
			OuterDMacNode.LoopbackSmac = SteeringNode.FieldValue;
			SteeringNode.SmacEncapsulationLoopbackType = OuterDMacNode.IsRoce or OuterDMacNode.RoCE ? LoopbackRoceOverlay : RegularLoopback;
			SteeringNode.LoopbackDmac = OuterDMacNode.FieldValue;
		};
		return SteeringNode.SmacEncapsulationLoopbackType;
	};

	UpdateRoceOverVxlanPacketFields(Packet : NetworkPacket,RoceOverVxlanNode : SteeringNode,IPSecTunneled : bool = FALSE) is {
		Packet.MACHeader().DestAddr = RoceOverVxlanNode.ParentNodes.first(it.Kind == Mac).FieldValue;
		if RoceOverVxlanNode.ParentNodes.has(it.Kind == Vlan) {
			for each (VlanTag) in RoceOverVxlanNode.ParentNodes.first(it.Kind == Vlan).VlanList {
				Packet.MACHeader().MacInternalHeaders[index].EtherType =  VlanTag.EtherType;
				Packet.MACHeader().MacInternalHeaders[index].VlanID    =  VlanTag.VlanID;
				Packet.MACHeader().MacInternalHeaders[index].CFI_DEI   =  VlanTag.CFI_DEI;
				Packet.MACHeader().MacInternalHeaders[index].PCP       =  VlanTag.PCP;
			};
		};
		if RoceOverVxlanNode.ParentNodes.has(it.Kind == Mpls) {
			for each (MplsLabel) in RoceOverVxlanNode.ParentNodes.first(it.Kind == Mpls).MplsLabelHeader.MPLSLabelStackList {
				Packet.MPLSHeader().MPLSLabelStackList[index].TTL           =  MplsLabel.TTL;
				Packet.MPLSHeader().MPLSLabelStackList[index].BottomOfStack =  MplsLabel.BottomOfStack;
				Packet.MPLSHeader().MPLSLabelStackList[index].TrafficClass  =  MplsLabel.TrafficClass;
				Packet.MPLSHeader().MPLSLabelStackList[index].Label         =  MplsLabel.Label;
			};
		};
		if RoceOverVxlanNode.ParentNodes.has(it.Kind in [Ipv4_5Tuple,Ipv4_5TupleByDecap]) {
			var Ipv4FieldValue : uint(bits:128) = RoceOverVxlanNode.ParentNodes.first(it.Kind in [Ipv4_5Tuple,Ipv4_5TupleByDecap]).FieldValue;
			Packet.IPv4Header().DestAddress = Ipv4FieldValue[127:96];
			Packet.IPv4Header().SrcAddress = Ipv4FieldValue[95:64];
			if not IPSecTunneled {
				Packet.UDPHeader().SrcPort = Ipv4FieldValue[63:48];
				Packet.UDPHeader().DestPort = Ipv4FieldValue[47:32];
			};
		};
		if RoceOverVxlanNode.ParentNodes.has(it.Kind in [Ipv4Src,Ipv4SrcByDecap]) {
			var Ipv4FieldValue : uint(bits:128) = RoceOverVxlanNode.ParentNodes.first(it.Kind in [Ipv4Src,Ipv4SrcByDecap]).FieldValue;
			Packet.IPv4Header().SrcAddress = Ipv4FieldValue[31:0];
		};
		if RoceOverVxlanNode.ParentNodes.has(it.Kind in [Ipv4Dst,Ipv4DstByDecap]) {
			var Ipv4FieldValue : uint(bits:128) = RoceOverVxlanNode.ParentNodes.first(it.Kind in [Ipv4Dst,Ipv4DstByDecap]).FieldValue;
			Packet.IPv4Header().DestAddress = Ipv4FieldValue[31:0];
		};
		if RoceOverVxlanNode.ParentNodes.has(it.Kind in [Ipv6Dst,Ipv6DstByDecap]) {
			Packet.IPv6Header().DestGID = RoceOverVxlanNode.ParentNodes.first(it.Kind in [Ipv6Dst,Ipv6DstByDecap]).FieldValue;
		};
		if RoceOverVxlanNode.ParentNodes.has(it.Kind in [Ipv6Src,Ipv6SrcByDecap]) {
			Packet.IPv6Header().SrcGID = RoceOverVxlanNode.ParentNodes.first(it.Kind in [Ipv6Src,Ipv6SrcByDecap]).FieldValue;
		};
		if RoceOverVxlanNode.ParentNodes.has(it.Kind in [Ipv6L4,Ipv6L4ByDecap,L4Only,L4OnlyByDecap]) {
			var L4FieldValue : uint(bits:128) = RoceOverVxlanNode.ParentNodes.first(it.Kind in [Ipv6L4,Ipv6L4ByDecap,L4Only,L4OnlyByDecap]).FieldValue;
			if not IPSecTunneled {
				Packet.UDPHeader().DestPort = L4FieldValue[111:96];
				Packet.UDPHeader().SrcPort = L4FieldValue[79:64];
			};
		};
		if RoceOverVxlanNode.ParentNodes.has(it.Kind in [TunnelType]) {
			Packet.VXLANHeader().VNI = RoceOverVxlanNode.ParentNodes.first(it.Kind == TunnelType).FieldValue[63:40];
			Packet.VXLANHeader().Reserved2 = RoceOverVxlanNode.ParentNodes.first(it.Kind == TunnelType).FieldValue[39:32];
		};
	};

	NeedToChangePacketPrio(SteeringNode : SteeringNode, Packet : NetworkPacket) : bool is {
		result = FALSE;
		var ConfigRequirements : ConfigRequirements = new;
		ConfigRequirements.GvmiNum = SteeringNode.SteeringTree.Gvmi;
		ConfigRequirements.PortNum = SteeringNode.SteeringTree.Port;
		var Direction: NetworkPacketDirection = SteeringNode.RemoteFlow ? Outbound: Inbound;
		var PrioSourceType : PrioSourceType;
		if Direction == Inbound {
			PrioSourceType = HANDLERS(Config).GetLogicalPortConfigInfoList().key(SteeringNode.SteeringTree.Port).PrioInfo.RxPrioSourceType;
		} else {
			PrioSourceType = HANDLERS(Config).GetLogicalPortConfigInfoList().key(SteeringNode.SteeringTree.Port).PrioInfo.SxPrioSourceType
		};
		if PrioSourceType in [VlanDefault] and Packet.MACHeader().MacInternalHeaders.is_empty() {
			return FALSE;
		};
		//if PrioSourceType in [VlanDefault] and (HANDLERS(Config).GetGvmiContext(ConfigRequirements).SxTagDataSize + (HANDLERS(Config).GetGvmiContext(ConfigRequirements).SxCvlanTaggingMode != None).as_a(uint) != 0) {
		//  return FALSE;
		//};
		//var PacketPrio : uint(bits:3) = Packet.GetPrioForBufferQueueCalc(SteeringNode.SteeringTree.Port, Direction);
		//if PacketPrio == HANDLERS(Config).GetLogicalPortConfigInfoList().key(SteeringNode.SteeringTree.Port).PrioInfo.DefaultPrio {
		//  return FALSE;
		//};
		ConfigRequirements.Required.add(Mac);
		ConfigRequirements.Mac = SteeringNode.FieldValue;
		if PrioSourceType in [DscpDefault, MplsExpDscpDefault, MplsExpDscpVlanDefault, VlanMplsExpDscpDefault] {
			ConfigRequirements.Required.add(RoCEType);
			ConfigRequirements.RoCETypeList = {RRoCEoIPv4; RRoCEoIPv6; RRoCEUdpoIPv4; RRoCEUdpoIPv6};
		} else if PrioSourceType in [VlanDefault] {
			ConfigRequirements.Required.add(SxInsertVlan);
			ConfigRequirements.SxInsertVlan = TRUE;
		};
		return not HANDLERS(Config).CanGetGidTableEntry(ConfigRequirements);
	};

	//=================================================================================================================================================//
	//================================================= MeetsRequirements =============================================================================//
	//=================================================================================================================================================//

	MeetsRequirements(SteeringNode : SteeringNode, Requirements : SteeringNodeRequirements) : bool is also {
		var SteeringBranch : list of SteeringNode = SteeringNode.GetSteeringBranch();
		var GvmiPortNoVlan: bool  =
		((Gvmi not in Requirements.Required or (SteeringNode.SteeringTree.Gvmi == Requirements.Gvmi)) and
			(Port not in Requirements.Required or (SteeringNode.SteeringTree.Port == Requirements.Port)) and
			MeetsRequirementsNoTunneling(SteeringBranch, Requirements) and
			MeetsRequirementsMandatoryNoVlan(SteeringBranch, Requirements) and
			MeetsRequirementsMandatoryNoMpls(SteeringBranch, Requirements) and
			MeetsRequirementsMandatoryNoSvlan(SteeringBranch, Requirements) and
			MeetsRequirementsNoReWriteOnTcp(SteeringBranch, Requirements) and
			MeetsRequiredmentsNoNonReversableReWriteActionsOnDmac(SteeringBranch, Requirements));
		var FirstVlanVlanPrioRange: bool = MeetsRequirementsFirstVlan(SteeringBranch, Requirements) and MeetsRequirementsVlanPrioRange(SteeringBranch, Requirements);
		var MplsPrioRange : bool = MeetsRequirementsMplsPrioRange(SteeringBranch, Requirements);
		var PushVlanPrioMeets : bool = MeetsRequirementsPushVlanPrio(SteeringBranch, Requirements);
		var PushMplsPrioMeets : bool = MeetsRequirementsPushMplsPrio(SteeringBranch, Requirements);
		var PushVlanOrMplsMoreThanMeets : bool = MeetsRequirementsPushVlanOrMplsMoreThan(SteeringBranch, Requirements);
		var PushVlanOrMplsLessEqualThanMeets : bool = MeetsRequirementsPushVlanOrMplsLessEqualThan(SteeringBranch, Requirements);
		result = GvmiPortNoVlan and FirstVlanVlanPrioRange and MplsPrioRange and PushVlanOrMplsMoreThanMeets and PushVlanPrioMeets and PushMplsPrioMeets and PushVlanOrMplsLessEqualThanMeets;
		result = result and MeetsRequirementsRRoceType(SteeringBranch, Requirements);
		result = result and MeetsRequirementsMplsIpOffset(SteeringBranch, Requirements);
		result = result and MeetsRequirementsDscpIpOffset(SteeringBranch, Requirements);
		result = result and MeetsRequirementsNoRoCEoVxlan(SteeringBranch, Requirements);
		result = result and MeetsRequirementsNoL3Encapsulation(SteeringBranch, Requirements);
		result = result and MeetsRequirementsRemoteRoCEoVxlanPrioRange(SteeringBranch, Requirements);
		result = result and MeetsRequirementsCheckLocalRoCEoVxlan(SteeringBranch, Requirements);
		result = result and MeetsRequirementsCheckRoCEEncapsulation(SteeringBranch, Requirements);
		result = result and MeetsRequirementsNoRoCEEncap(SteeringBranch, Requirements);
		result = result and MeetsRequirementsDestGidRoceAndLoopback(SteeringBranch,Requirements);
		result = result and MeetsRequirementsGidInfo(SteeringBranch, Requirements);
		result = result and MeetsRequirementsPrioFromSteering(SteeringBranch, Requirements);
		result = result and MeetsRequirementsRemoteFlow(SteeringBranch, Requirements);
		result = result and MeetsRequirementsInUse(SteeringBranch, Requirements);
		result = result and MeetsRequirementsRoce(SteeringBranch, Requirements);
		result = result and MeetsRequirementsNoIpsec(SteeringBranch, Requirements);
		result = result and MeetsRequirementsNoConnectionTracking(SteeringBranch, Requirements);
		result = result and MeetsRequirementsNoTra(SteeringBranch, Requirements);
		result = result and MeetsRequirementsEncapDscpIpMinOffst(SteeringBranch, Requirements);
		------print for debug------
		messagef(FULL, "FlowGenerator.MeetsRequirements: Required - %s, GvmiPortNoVlan = %s, MeetsRequirementsFirstVlan=%s, MeetsRequirementsVlanPrioRange=%s",
			Requirements.Required, GvmiPortNoVlan, MeetsRequirementsFirstVlan(SteeringBranch, Requirements), MeetsRequirementsVlanPrioRange(SteeringBranch, Requirements));
	};

	MeetsRequirementsNoRoCEEncap(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		return !SteeringBranch.has(it.IsRoce) or NoRoCEEncap not in Requirements.Required or not SteeringBranch.SxSteeringModificationActions.SxModificationActionType.has(it in [Encapsulation]);
	};

	MeetsRequirementsCheckLocalRoCEoVxlan(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		if !SteeringBranch.has(it.IsRoce) or CheckLocalRoCEoVxlan not in Requirements.Required or not SteeringBranch.has(it.RoceOverVXLAN) {
			return TRUE;
		};
		if HANDLERS(Config).GetLogicalPortConfigInfoList().key(SteeringBranch.first(TRUE).SteeringTree.Port).PrioInfo.RxPrioSourceType not in [VlanDefault] or
			not (SteeringBranch.max_value(it.VlanList.size()) + SteeringBranch.count(it.SxSteeringModificationActions.SxModificationActionType.has(it == PushVlan)) == 0) {
			return TRUE;
		};
		var RequirementsForGidInfo : SteeringNodeRequirements = deep_copy(Requirements);
		var HasSxInsertVlan : bool = MeetsRequirementsGidInfo(SteeringBranch, Requirements);
		var RoCEoVxlanSteeringNode : SteeringNode = SteeringBranch.first(it.RoceOverVXLAN);
		var EncapsulatedPacket : list of byte= RoCEoVxlanSteeringNode.EncapsulationDataBase.EncapsulatedSteeringEntry[0..(RoCEoVxlanSteeringNode.EncapsulationDataBase.EncapsulatedSteeringEntry.size()-RoCEoVxlanSteeringNode.EncapsulationDataBase.EncapsulatedOffset-1)];
		var UnpackedEncapsulatedPacket : NetworkPacket = new;
		UnpackedEncapsulatedPacket.SetDontCheckOnUnpack();
		compute UnpackedEncapsulatedPacket.Unpack(EncapsulatedPacket, MAC, FALSE);
		var PacketPrio : uint(bits:3) = UnpackedEncapsulatedPacket.GetPrioForBufferQueueCalc(Requirements.Port, Inbound); -- Remote->Local flow only, encap is added in Remote

		return PacketPrio == HANDLERS(Config).GetLogicalPortConfigInfoList().key(SteeringBranch.first(TRUE).SteeringTree.Port).PrioInfo.DefaultPrio; -- or HasSxInsertVlan;
	};

	MeetsRequirementsCheckRoCEEncapsulation(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		if !SteeringBranch.has(it.IsRoce) or CheckRoCEEncapsulation not in Requirements.Required or not SteeringBranch.SxSteeringModificationActions.SxModificationActionType.has(it in [Encapsulation]) {
			return TRUE;
		};
		var ConfigRequirements = new with {
			it.GvmiNum = SteeringBranch.first(TRUE).SteeringTree.Gvmi;
			it.PortNum = SteeringBranch.first(TRUE).SteeringTree.Port;
		};
		if (HANDLERS(Config).GetLogicalPortConfigInfoList().key(SteeringBranch.first(TRUE).SteeringTree.Port).PrioInfo.SxPrioSourceType in [VlanDefault] and
				(HANDLERS(Config).GetGvmiContext(ConfigRequirements).SxTagDataSize + (HANDLERS(Config).GetGvmiContext(ConfigRequirements).SxCvlanTaggingMode != None).as_a(uint) != 0)) {
			return TRUE;
		};
		var EncapsulationSteeringNode : SteeringNode = SteeringBranch.first(it.SxSteeringModificationActions.SxModificationActionType.has(it in [Encapsulation]));
		var EncapsulatedPacket : list of byte= EncapsulationSteeringNode.EncapsulationDataBase.EncapsulatedSteeringEntry[0..(EncapsulationSteeringNode.EncapsulationDataBase.EncapsulatedSteeringEntry.size()-EncapsulationSteeringNode.EncapsulationDataBase.EncapsulatedOffset-1)];
		var UnpackedEncapsulatedPacket : NetworkPacket = new;
		UnpackedEncapsulatedPacket.SetDontCheckOnUnpack();
		compute UnpackedEncapsulatedPacket.Unpack(EncapsulatedPacket, MAC, FALSE);
		var PacketPrio : uint(bits:3) = UnpackedEncapsulatedPacket.GetPrioForBufferQueueCalc(SteeringBranch.first(TRUE).SteeringTree.Port, Outbound); -- Remote->Local flow only, encap is added in Remote

		if PacketPrio == HANDLERS(Config).GetLogicalPortConfigInfoList().key(SteeringBranch.first(TRUE).SteeringTree.Port).PrioInfo.DefaultPrio {
			return TRUE;
		} else if HANDLERS(Config).GetLogicalPortConfigInfoList().key(SteeringBranch.first(TRUE).SteeringTree.Port).PrioInfo.SxPrioSourceType in [DscpDefault, MplsExpDscpDefault, MplsExpDscpVlanDefault, VlanMplsExpDscpDefault] {
			ConfigRequirements.Required.add(Mac);
			ConfigRequirements.Required.add(RoCEType);
			ConfigRequirements.Mac = SteeringBranch.first(it.Kind in [Mac,MacByDecap]).FieldValue;
			ConfigRequirements.RoCETypeList = {RRoCEoIPv4; RRoCEoIPv6; RRoCEUdpoIPv4; RRoCEUdpoIPv6};
			return HANDLERS(Config).CanGetGidTableEntry(ConfigRequirements);
		} else if HANDLERS(Config).GetLogicalPortConfigInfoList().key(SteeringBranch.first(TRUE).SteeringTree.Port).PrioInfo.SxPrioSourceType in [VlanDefault] {
			ConfigRequirements.Required.add(Mac);
			ConfigRequirements.Required.add(SxInsertVlan);
			ConfigRequirements.Mac = SteeringBranch.first(it.Kind in [Mac,MacByDecap]).FieldValue;
			ConfigRequirements.SxInsertVlan = TRUE;
			if QpAllocationGidTableEntryRequirements in Requirements.Required {
				if Requirements.QpAllocationGidTableEntryRequirements.HasRequirement(SxInsertVlan) {
					if Requirements.QpAllocationGidTableEntryRequirements.SxInsertVlan == FALSE {
						return FALSE;
					};
				} else {
					var RoCELoopbackSteeringRequirements : SteeringNodeRequirements = deep_copy(Requirements);
					RoCELoopbackSteeringRequirements.QpAllocationGidTableEntryRequirements.Required.add(SxInsertVlan);
					RoCELoopbackSteeringRequirements.QpAllocationGidTableEntryRequirements.SxInsertVlan = TRUE;
					if not MeetsRequirementsDestGidRoceAndLoopback(SteeringBranch, RoCELoopbackSteeringRequirements) {
						return FALSE;
					};
				};

			};
			return HANDLERS(Config).CanGetGidTableEntry(ConfigRequirements);
		};
	};

	MeetsRequirementsPrioFromSteering(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements) : bool is {
		if PrioFromSteering not in Requirements.Required {
			return TRUE;
		};
		var Port : uint = SteeringBranch.first(TRUE).SteeringTree.Port;
        if SteeringBranch.has(it.SxMACSecHostType != None) {
            if SteeringBranch.first(it.SxMACSecHostType != None).SxSecTagMode == OverSrcAddr or HANDLERS(Config).GetLogicalPortConfigInfoList().key(Port).PrioInfo.RxPrioSourceType not in [VlanDefault] {
                return HANDLERS(Config).GetLogicalPortConfigInfoList().key(Port).PrioInfo.DefaultPrio in Requirements.PrioFromSteering;
            } else {
                return TRUE;
            };
        };
		if not SteeringBranch.has(it.EncapsulationDataBase != NULL) {
			return TRUE;
		};
		messagef(HIGH,"MeetsRequirementsPrioFromSteering: Requirements.PrioFromSteering %s EncapsulatedPacketPrio 0x%x",
			Requirements.PrioFromSteering, SteeringBranch.first(it.EncapsulationDataBase != NULL).EncapsulationDataBase.Packet.GetPrioForBufferQueueCalc(Port, Outbound)) {
			SteeringBranch.first(it.EncapsulationDataBase != NULL).EncapsulationDataBase.Packet.PrintMe();
		};
		return SteeringBranch.first(it.EncapsulationDataBase != NULL).EncapsulationDataBase.Packet.GetPrioForBufferQueueCalc(Port, Outbound) in Requirements.PrioFromSteering;
	};

	MeetsRequirementsGidInfo(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		if !SteeringBranch.has(it.IsRoce) or (ReceiveNoVlan not in Requirements.Required and NeedVlanInRoce not in Requirements.Required and
				QpAllocationGidTableEntryRequirements not in Requirements.Required and NeedRRoce not in Requirements.Required and
				not (NeedVlanInRoce not in Requirements.Required and CanAddSxInsertVlan in Requirements.Required and SteeringBranch.max_value(it.VlanList.size()) >= HANDLERS(Config).GetPortConfigInfo(SteeringBranch[0].SteeringTree.Port).PrioInfo.IpMaxOffsetFromMac)) {
			return TRUE;
		};
		var ConfigRequirements = new with {
			it.GvmiNum = SteeringBranch.first(TRUE).SteeringTree.Gvmi;
			it.PortNum = SteeringBranch.first(TRUE).SteeringTree.Port;
		};
		ConfigRequirements.Required = {Mac};
		ConfigRequirements.Mac = SteeringBranch.first(it.Kind in [Mac,MacByDecap]).FieldValue;
		if NeedVlanInRoce not in Requirements.Required and CanAddSxInsertVlan in Requirements.Required and HANDLERS(Config).GetLogicalPortConfigInfoList().key(SteeringBranch.first(TRUE).SteeringTree.Port).PrioInfo.SxPrioSourceType in [DscpDefault, MplsExpDscpDefault, VlanMplsExpDscpDefault, MplsExpDscpVlanDefault] {
			if SteeringBranch.max_value(it.VlanList.size()) >= HANDLERS(Config).GetPortConfigInfo(SteeringBranch.first(TRUE).SteeringTree.Port).PrioInfo.IpMaxOffsetFromMac {
				messagef(HIGH,"MeetsRequirementsGidInfo - Added Requirement SxInsertVlan = FALSE with MAC 0x%x.", ConfigRequirements.Mac);
				ConfigRequirements.Required.add(SxInsertVlan);
				ConfigRequirements.SxInsertVlan = FALSE;
			};
		};
		if ReceiveNoVlan in Requirements.Required {
			ConfigRequirements.Required.add(RxAllowNoVlan);
			ConfigRequirements.RxAllowNoVlan = TRUE;
		};
		if NeedVlanInRoce in Requirements.Required {// and SteeringBranch.max_value(it.VlanList.size()) == 0 { -- if we have Vlan in SteeringList, prio can be != Default
			ConfigRequirements.Required.add(RxVlanAllowed);
            	ConfigRequirements.Required.add(SxInsertVlan);
				ConfigRequirements.SxInsertVlan = TRUE;
		};
		if NeedRRoce in Requirements.Required {
			ConfigRequirements.Required.add(RoCEType);
			ConfigRequirements.RoCETypeList = {RRoCEoIPv4; RRoCEoIPv6; RRoCEUdpoIPv4; RRoCEUdpoIPv6};
		};
		return HANDLERS(Config).CanGetGidTableEntry(ConfigRequirements);
	};

	MeetsRequirementsRemoteRoCEoVxlanPrioRange(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		messagef(HIGH, "Najeeb DB - MeetsRequirementsRemoteRoCEoVxlanPrioRange - Start");
		if RemoteRoCEoVxlanPrioRange in Requirements.Required and (SteeringBranch.has(it.SxIPSecHostType == Unaware and it.SxIPSecMode in [Tunneled_IPv4,Tunneled_IPv6]) or SteeringBranch.has(it.RoceOverVXLAN)) {
			messagef(HIGH, "Najeeb DB - MeetsRequirementsRemoteRoCEoVxlanPrioRange - RoceOverVXLAN=%s SxIPSecMode=%s",SteeringBranch.has(it.RoceOverVXLAN),not SteeringBranch.has(it.RoceOverVXLAN));
			var EncapSteeringNode : SteeringNode;
			if SteeringBranch.has(it.RoceOverVXLAN) {
				EncapSteeringNode = SteeringBranch.first(it.RoceOverVXLAN);
			} else {
				EncapSteeringNode = SteeringBranch.first(it.SxIPSecHostType == Unaware and it.SxIPSecMode in [Tunneled_IPv4,Tunneled_IPv6] and it.SteeringNodeHasInsertWithPointer(SX));
			};
			messagef(HIGH, "Najeeb DB - MeetsRequirementsRemoteRoCEoVxlanPrioRange - EncapSteeringNode.NodeIndex=%s",EncapSteeringNode.NodeIndex);
			var EncapsulatedPacket : list of byte= EncapSteeringNode.EncapsulationDataBase.EncapsulatedSteeringEntry[0..(EncapSteeringNode.EncapsulationDataBase.EncapsulatedSteeringEntry.size()-EncapSteeringNode.EncapsulationDataBase.EncapsulatedOffset-1)];
			var UnpackedEncapsulatedPacket : NetworkPacket = new;
			UnpackedEncapsulatedPacket.SetDontCheckOnUnpack();
			compute UnpackedEncapsulatedPacket.Unpack(EncapsulatedPacket, MAC, FALSE);
			var PacketPrio : uint(bits:3) = UnpackedEncapsulatedPacket.GetPrioForBufferQueueCalc(Requirements.Port, Inbound); -- Remote->Local flow only, encap is added in Remote
			messagef(HIGH, "Najeeb DB - MeetsRequirementsRemoteRoCEoVxlanPrioRange - PacketPrio=%s",PacketPrio);
			return PacketPrio.as_a(int) in Requirements.RemoteRoCEoVxlanPrioRange;
		} else {
			return TRUE;
		};

	};

	MeetsRequirementsNoRoCEoVxlan(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		if NoRoCEoVxlan not in Requirements.Required {
			return TRUE;
		};
		return not SteeringBranch.has(it.RoceOverVXLAN);
	};

	MeetsRequirementsNoL3Encapsulation(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		if NoL3Encapsulation not in Requirements.Required {
			return TRUE;
		};
		return not SteeringBranch.SxSteeringModificationActions.SxModificationActionType.has(it in [L3Encapsulation]);
	};
	MeetsRequirementsMplsIpOffset(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		if MplsIpOffset not in Requirements.Required or not SteeringBranch.has(it.Kind == Vlan) {
			return TRUE;
		};
		var NumOfVlansRequiredBySteering : uint = SteeringBranch.max_value(it.VlanList.size());
		NumOfVlansRequiredBySteering += SteeringBranch.SxSteeringModificationActions.all(it.SxModificationActionType == PushVlan).sum(it.SxPushVlans.size());
		result = NumOfVlansRequiredBySteering <= HANDLERS(Config).GetPortConfigInfo(Requirements.Port).PrioInfo.MplsMaxOffsetFromMac;
        result = result and not SteeringBranch.has(it.SxMACSecHostType != None);
	};

	MeetsRequirementsEncapDscpIpMinOffst(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		if EncapDscpIpMinOffst not in Requirements.Required {
			return TRUE;
		};

		if not SteeringBranch.last(TRUE).SteeringNodeInEncapsulationEnabledFlow(TRUE) {
			return TRUE;
		};
		var EncapPkt : NetworkPacket = SteeringBranch.last(it.SxSteeringModificationActions.SxModificationActionType.has(it in[Encapsulation,L3Encapsulation])).EncapsulationDataBase.Packet;
		var EncapDscpIpOfsst : uint = EncapPkt.MACHeader().MacInternalHeaders.size() + (EncapPkt.MPLSHeader() != NULL ? EncapPkt.MPLSHeader().MPLSLabelStackList.size() :0);
		return EncapDscpIpOfsst > Requirements.EncapDscpIpMinOffst;
	};

	MeetsRequirementsDscpIpOffset(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		if DscpIpOffset not in Requirements.Required {
			return TRUE;
		};
		if HANDLERS(Config).GetPortConfigInfo(SteeringBranch.first(TRUE).SteeringTree.Port).PrioInfo.RxPrioSourceType in [VlanMplsExpDscpDefault] and SteeringBranch.has(it.Kind == Vlan or it.Kind == Mpls) {
			return TRUE;
		};
		if HANDLERS(Config).GetPortConfigInfo(SteeringBranch.first(TRUE).SteeringTree.Port).PrioInfo.RxPrioSourceType in [MplsExpDscpVlanDefault,MplsExpDscpDefault] and SteeringBranch.has(it.Kind == Mpls) {
			return TRUE;
		};
		var AddExtraMpls : bit = SteeringBranch.all(it.MplsLabelHeader != NULL).MplsLabelHeader.MPLSLabelStackList.is_empty() ? 0 : 1 - SteeringBranch.all(it.MplsLabelHeader != NULL).MplsLabelHeader.MPLSLabelStackList.last(TRUE).BottomOfStack;
		var NumOfVlansRequiredBySteering : uint = SteeringBranch.max_value(it.VlanList.size());
		NumOfVlansRequiredBySteering += SteeringBranch.SxSteeringModificationActions.all(it.SxModificationActionType == PushVlan).sum(it.SxPushVlans.size());
		var NumOfMplsRequiredBySteering : uint = SteeringBranch.all(it.MplsLabelHeader != NULL).MplsLabelHeader.MPLSLabelStackList.size();
		NumOfMplsRequiredBySteering += SteeringBranch.SxSteeringModificationActions.all(it.SxModificationActionType == PushMpls).sum(it.MplsLabelsToPush.size());
		if (NumOfMplsRequiredBySteering + NumOfVlansRequiredBySteering + AddExtraMpls) < HANDLERS(Config).GetPortConfigInfo(Requirements.Port).PrioInfo.IpMaxOffsetFromMac {
			return TRUE;
		} else if (NumOfMplsRequiredBySteering + NumOfVlansRequiredBySteering + AddExtraMpls) == HANDLERS(Config).GetPortConfigInfo(Requirements.Port).PrioInfo.IpMaxOffsetFromMac {
			Requirements.Required.add(ReceiveNoVlan); -- Remote->Local flow, Local cannot allow getting more Vlan(from GID) from Remote, otherwise the prio of the incoming packet will be wrong (we are asked for a certain prio when reaching this region)
			return FALSE;
		};
        if SteeringBranch.has(it.SxMACSecHostType != None) {
			return FALSE;
		};
	};

	-- We want to check whether a node can be used for the QpAllocation (which will turn into DestQp) and could be a match for an exising LocalQp - using MAC
	MeetsRequirementsDestGidRoceAndLoopback(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements) : bool is {
		if QpAllocationGidTableEntryRequirements not in Requirements.Required or !SteeringBranch.has(it.IsRoce) {
			return TRUE;
		};
		var ConfigRequirements : ConfigRequirements = Requirements.QpAllocationGidTableEntryRequirements;
		ConfigRequirements.GvmiNum = SteeringBranch.first(TRUE).SteeringTree.Gvmi;
		ConfigRequirements.PortNum = Requirements.Port;
		ConfigRequirements.Required.add(Mac);
		ConfigRequirements.Mac = SteeringBranch.first(it.Kind in [Mac,MacByDecap]).FieldValue;
		return HANDLERS(Config).CanGetGidTableEntry(ConfigRequirements);
	};

	MeetsRequirementsRRoceType(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		if RRoceType not in Requirements.Required or !SteeringBranch.has(it.IsRoce) {
			return TRUE;
		};
		if (Requirements.RRoceType==RRoCEoIPv6 and SteeringBranch.has(it.IsRoce and it.Kind in [Ipv4_5Tuple,Ipv6L4]) or //ipv6 no udp
				Requirements.RRoceType==RRoCEoIPv4 and SteeringBranch.has(it.IsRoce and it.Kind in [Ipv4_5Tuple,Ipv6L4,Ipv6Dst,Ipv6Src]) or //ipv4 no udp
				Requirements.RRoceType==RRoCEUdpoIPv6 and SteeringBranch.has(it.IsRoce and it.Kind in [Ipv4_5Tuple]) or //ipv6 with udp
				Requirements.RRoceType==RRoCEUdpoIPv4 and SteeringBranch.has(it.IsRoce and it.Kind in [Ipv6L4,Ipv6Dst,Ipv6Src])) {  //ipv6 with udp
			return FALSE;
		} else {
			return TRUE;
		};
	};

	MeetsRequirementsRemoteFlow(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		result = (RemoteFlow not in Requirements.Required and not SteeringBranch.has(it.RemoteFlow)) or (RemoteFlow in Requirements.Required and SteeringBranch.has(it.RemoteFlow));
	};

	MeetsRequirementsInUse(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		result = (InUse not in Requirements.Required or not SteeringBranch.has(it.InUse!=Requirements.InUse));
	};

	MeetsRequirementsNoIpsec(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		result = (NoIpsec not in Requirements.Required or not SteeringBranch.has(it.RxSteeringInlineActions.has(it.RxInlineActionType in [IpsecUnaware,IpsecAware])));
	};

	MeetsRequirementsNoConnectionTracking(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		result = (NoConnectionTracking not in Requirements.Required or not SteeringBranch.has(it.RxSteeringInlineActions.has(it.RxInlineActionType == ASO_ConnectionTracking)));
	};

	MeetsRequirementsNoTra(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		result = (NoTra not in Requirements.Required or not SteeringBranch.has(it.RxSteeringInlineActions.has(it.RxInlineActionType == Tra)));
	};

	MeetsRequirementsRoce(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		result = (RoCE not in Requirements.Required or not SteeringBranch.has(it.RoCE!=Requirements.RoCE));
	};

	MeetsRequirementsNoTunneling(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		result = NoTunneling not in Requirements.Required or !SteeringBranch.has(it.Kind == TunnelType and it.ValueType != NoValuesAllowed);
	};

	MeetsRequirementsMandatoryNoVlan(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		result = NoVlan not in Requirements.Required or !SteeringBranch.has(it.Kind == Vlan and it.ValueType != NoValuesAllowed);
	};

	MeetsRequirementsMandatoryNoMpls(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		result = NoMpls not in Requirements.Required or !SteeringBranch.has(it.Kind == Mpls and it.ValueType != NoValuesAllowed);
	};

	MeetsRequirementsMandatoryNoSvlan(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		result = NoSvlan not in Requirements.Required or !SteeringBranch.has(it.Kind == Vlan and it.ValueType == CertainValue and it.VlanList.has(it.EtherType == HANDLERS(Config).NetworkPacketConfig.SVLAN_ETHERTYPE));
	};

	MeetsRequirementsNoReWriteOnTcp(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements) : bool is {
		result = NoReWriteOnTcp not in Requirements.Required or !SteeringBranch.has(it.RxSteeringModificationActions.DstDwOffset.has(it in [OuterEthL4_Tcp]));
	};

	MeetsRequiredmentsNoNonReversableReWriteActionsOnDmac(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements) : bool is {
		result = NoNonReversableReWriteActionsOnDmac not in Requirements.Required or !SteeringBranch.has(it.RxSteeringModificationActions.has(it.DstDwOffset in [OUTER_DMAC_DEFINER_FIELDS] and it.RxModificationActionType in [Copy, Set]));
	};

	MeetsRequirementsPushVlanPrio(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		if SteeringPushVlanPrio not in Requirements.Required {
			return TRUE;
		};
		var SxPushSteeringNode : SteeringNode;
		if SteeringBranch.SxSteeringModificationActions.SxModificationActionType.has(it == PushVlan) {
			SxPushSteeringNode = SteeringBranch.all(it.SxSteeringModificationActions.SxModificationActionType.has(it == PushVlan)).max(it.LevelInTree);
		};
		if SxPushSteeringNode != NULL {
			return MatchVlanPrio(SxPushSteeringNode.SxSteeringModificationActions.SxPushVlans.last(TRUE),{Requirements.SteeringPushVlanPrio});
		} else {
			return TRUE;
		};
	};

	MeetsRequirementsPushMplsPrio(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		if SteeringPushMplsPrio not in Requirements.Required {
			return TRUE;
		};
		if HANDLERS(Config).GetLogicalPortConfigInfoList().key(Requirements.Port).PrioInfo.SxPrioSourceType not in [MplsExpDscpDefault, MplsExpDscpVlanDefault, VlanMplsExpDscpDefault] {
			return TRUE;
		};
		var ConfigRequirements = new with {
			it.GvmiNum = SteeringBranch.first(TRUE).SteeringTree.Gvmi;
			it.PortNum = Requirements.Port;
		};
		var SxPushSteeringNode : SteeringNode;
		if SteeringBranch.SxSteeringModificationActions.SxModificationActionType.has(it == PushMpls) {
			SxPushSteeringNode = SteeringBranch.all(it.SxSteeringModificationActions.SxModificationActionType.has(it == PushMpls)).max(it.LevelInTree);
		};
		if SxPushSteeringNode != NULL {
			return HANDLERS(Config).Mpls2Prio(ConfigRequirements, SxPushSteeringNode.SxSteeringModificationActions.first(it.SxModificationActionType == PushMpls).MplsLabelsToPush.first(TRUE).TrafficClass) == Requirements.SteeringPushMplsPrio;
		} else {
			return TRUE;
		};
	};

	MeetsRequirementsPushVlanOrMplsMoreThan(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		if PushVlanOrMplsMoreThan not in Requirements.Required {
			return TRUE;
		};
		var MplsLabelHeaderBranch : list of MPLSHeader = SteeringBranch.MplsLabelHeader.all(it != NULL);
		if MplsLabelHeaderBranch.is_empty() {
			var AddExtraMpls : bit = MplsLabelHeaderBranch.MPLSLabelStackList.is_empty() ? 0 : 1 - MplsLabelHeaderBranch.MPLSLabelStackList.last(TRUE).BottomOfStack;
			return SteeringBranch.SxSteeringModificationActions.count(it.SxModificationActionType == PushVlan) + SteeringBranch.all(it.SxSteeringModificationActions.SxModificationActionType.has(it == PushMpls)).SxSteeringModificationActions.MplsLabelsToPush.size() + MplsLabelHeaderBranch.MPLSLabelStackList.size()  + AddExtraMpls > Requirements.PushVlanOrMplsMoreThan;
		} else {
			return FALSE;
		};
	};

	MeetsRequirementsPushVlanOrMplsLessEqualThan(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements) : bool is {
		if PushVlanOrMplsLessEqualThan not in Requirements.Required {
			return TRUE;
		};
		var MplsLabelHeaderBranch : list of MPLSHeader = SteeringBranch.MplsLabelHeader.all(it != NULL);
		if MplsLabelHeaderBranch.is_empty() {
			var AddExtraMpls : bit = MplsLabelHeaderBranch.MPLSLabelStackList.is_empty() ? 0 : 1 - MplsLabelHeaderBranch.MPLSLabelStackList.last(TRUE).BottomOfStack;
			return SteeringBranch.SxSteeringModificationActions.count(it.SxModificationActionType == PushVlan) + SteeringBranch.all(it.SxSteeringModificationActions.SxModificationActionType.has(it == PushMpls)).SxSteeringModificationActions.MplsLabelsToPush.size() + MplsLabelHeaderBranch.MPLSLabelStackList.size() + AddExtraMpls <= Requirements.PushVlanOrMplsLessEqualThan;
		} else {
			return FALSE
		};
	};

	MeetsRequirementsFirstVlan(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		result =
		(FirstVlan not in Requirements.Required or
			SteeringBranch.has(it.Kind == Vlan and it.ValueType == CertainValue and
				MatchVlanData(it.VlanList[0], Requirements.FirstVlanData, Requirements.FirstVlanValid)) or
			!SteeringBranch.has(it.Kind == Vlan and it.ValueType == CertainValue) or
			!SteeringBranch.has(it.Kind == Vlan));
		if FirstVlan in Requirements.Required and !Requirements.NoVlanAllowed and !SteeringBranch.has(it.Kind == Vlan) {
			return FALSE;
		};
	};

	MeetsRequirementsMplsPrioRange(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements) : bool is {
		if MplsPrioRange not in Requirements.Required or not SteeringBranch.has(it.Kind == Mpls) or SteeringBranch.first(it.Kind == Mpls).MplsLabelHeader == NULL {
			return TRUE;
		};
		var ConfigRequirements = new with {
			it.GvmiNum = SteeringBranch.first(TRUE).SteeringTree.Gvmi;
			it.PortNum = Requirements.Port;
		};
		var AllowedMplss : list of uint(bits:3);
		for each in Requirements.MplsPrioRange {
			AllowedMplss.add(HANDLERS(Config).Prio2Mpls(ConfigRequirements, Requirements.MplsPrioRange[index].as_a(uint(bits:3))));
		};
		AllowedMplss = AllowedMplss.sort(it).unique(it);
		return AllowedMplss.has(it == SteeringBranch.first(it.Kind == Mpls).MplsLabelHeader.MPLSLabelStackList[0].TrafficClass);
	};

	MeetsRequirementsVlanPrioRange(SteeringBranch : list of SteeringNode, Requirements : SteeringNodeRequirements): bool is {
		result = (VlanPrioRange not in Requirements.Required);
        result = result or SteeringBranch.has(it.Kind == Vlan and it.ValueType == CertainValue and MatchVlanPrio(it.VlanList[0], Requirements.VlanPrioRange));
        result = result or (SteeringBranch.has(it.Kind == Vlan) and !SteeringBranch.has(it.Kind == Vlan and it.ValueType == CertainValue));
        result = result or (DefaultPrio in Requirements.Required and !SteeringBranch.has(it.Kind == Vlan));
	    var DefaultPrio : uint(bits:3) = HANDLERS(Config).GetLogicalPortConfigInfoList().key(SteeringBranch.first(TRUE).SteeringTree.Port).PrioInfo.DefaultPrio;
        result = result or (SteeringBranch.has(it.SxMACSecHostType != None) and (!SteeringBranch.has(it.SxSecTagMode == OverSrcAddr) or Requirements.VlanPrioRange.has(it == DefaultPrio)));
	};

	//=================================================================================================================================================//
	//================================================= SxMeetRequirements ============================================================================//
	//=================================================================================================================================================//

	MeetSxRequirmentRoceTypePktType(Mac : uint (bits:48),Gvmi : uint (bits:16),Port : uint,SxpSteeringReq :SxpGenSteeringReq) : bool is {
		var ConfigRequirements : ConfigRequirements = new with {
			.GvmiNum = Gvmi;
			.PortNum = Port;
		};
		var GvmiInfo: GvmiInfo;
		if (ConfigRequirements.GvmiNum == HANDLERS(Config).GlobalGvmiInfo.GvmiNum) {
			GvmiInfo = HANDLERS(Config).GlobalGvmiInfo;
		} else {
			GvmiInfo = HANDLERS(Config).GetActiveGvmis().key(ConfigRequirements.GvmiNum);
		};
		if GvmiInfo != NULL {
			var CurGvmiContext : GvmiContext = GvmiInfo.GvmiContexts.key(ConfigRequirements.PortNum);
			if CurGvmiContext != NULL {
				if CurGvmiContext.GidTable.has(it.MyMac == Mac) { // ROCE
					case SxpSteeringReq.PktType {
						RoCE : {
							return CurGvmiContext.GidTable.first(it.MyMac == Mac).RoCEType == RoCEoGrh;
						};
						RRoCE_IP : {
							if SxpSteeringReq.L3EtherType == IPv4 {
								return CurGvmiContext.GidTable.first(it.MyMac == Mac).RoCEType in [RRoCEoIPv4];
							} else if SxpSteeringReq.L3EtherType == IPv6 {
								return CurGvmiContext.GidTable.first(it.MyMac == Mac).RoCEType in [RRoCEoIPv6];
							} else {
								DUTError(558899,appendf("SxpSteeringReq with PktType=RRoCE_IP while L3EtherType not in [IPv4,IPv6]"));
							};
						};
						RRoCE_UDP : {
							if SxpSteeringReq.L4Protocol != UDP {
								DUTError(558899,appendf("SxpSteeringReq with PktType=RRoCE_UDP while L4EtherType!=UDP"));
							};
							if SxpSteeringReq.L3EtherType == IPv4 {
								return CurGvmiContext.GidTable.first(it.MyMac == Mac).RoCEType in [RRoCEUdpoIPv4];
							} else if SxpSteeringReq.L3EtherType == IPv6 {
								return CurGvmiContext.GidTable.first(it.MyMac == Mac).RoCEType in [RRoCEUdpoIPv6];
							} else {
								DUTError(558899,appendf("SxpSteeringReq with PktType=RRoCE_UDP while L3EtherType not in [IPv4,IPv6]"));
							};
						};
					};
				};
			};
		};
	};

	MeetSxLayersRequirements(SteeringNode : SteeringNode, SxpSteeringReq :SxpGenSteeringReq) : bool is {
		var SteeringBranch : list of SteeringNode = SteeringNode.GetSteeringBranch();
		result = TRUE;
		if SxpSteeringReq.PktType == IB{
			result = result and SteeringBranch.has(it.Kind == Lid and it.HairPinMode in [None]);
			if SxpSteeringReq.HasGRH {
				result = result and SteeringBranch.has(it.Kind == Gid);
			} else if HANDLERS(LocalQp).FlowGenerator.GvmiResolutionMode == GID {
				return FALSE;
			};
		};
		if SxpSteeringReq.PktType == Eth or (SxpSteeringReq.PktType == IB and SxpSteeringReq.IPoIB){
			if SxpSteeringReq.L3EtherType == IPv4 {
				result = SteeringBranch.has(it.Kind == Ipv4_5Tuple and it.HairPinMode == None);
			} else if SxpSteeringReq.L3EtherType == IPv6 {
				result = SteeringBranch.has(it.Kind in [Ipv6Dst,Ipv6Src] and it.HairPinMode == None);
			} else {
				result = SteeringBranch.has(it.Kind in [Mac] and not (it.HairPinMode not in [None]));
			};
			if SxpSteeringReq.L4Protocol in [TCP,UDP] {
				result = result and SteeringBranch.has(it.Kind == Ipv6L4 and it.HairPinMode == None);
			};
			if SxpSteeringReq.HasMPLS {
				result = result and SteeringBranch.has(it.Kind == Mpls and it.HairPinMode == None);
			} else {
				result = result and not SteeringBranch.has(it.Kind == Mpls);
			};
		};
		if SxpSteeringReq.PktType in [RoCE,RRoCE_IP,RRoCE_UDP] {
			result = result and SteeringBranch.has(it.Kind == Mac and not (it.HairPinMode not in [None]));
			if result {
				result = result and MeetSxRequirmentRoceTypePktType(SteeringBranch.first(it.Kind == Mac).FieldValue[47:0],SteeringBranch.first(it.Kind == Mac).SteeringTree.Gvmi,SteeringBranch.first(it.Kind == Mac).SteeringTree.Port,SxpSteeringReq);
			};
		};
		if SxpSteeringReq.PktType not in [RoCE,RRoCE_IP,RRoCE_UDP,IB,Eth]{ return FALSE; };
		messagef(HIGH, "FlowGenerator.MeetSxRequirements: ") {
			SxpSteeringReq.PrintMe();
		};
	};

	MeetSxRequirements(SteeringNode : SteeringNode, SxpSteeringReq : SxpGenSteeringReq) : bool is {

		var SteeringBranch : list of SteeringNode = SteeringNode.GetSteeringBranch();
		if SxpSteeringReq.PktType in [RoCE,RRoCE_IP,RRoCE_UDP] {
			result = SteeringBranch.has(it.IsRoce == TRUE);
			result = result and MeetSxLayersRequirements(SteeringNode, SxpSteeringReq);
		} else if SxpSteeringReq.PktType == IB and SxpSteeringReq.IPoIB{
			result = SteeringBranch.has(it.IsRoce == FALSE and it.IBSteeringMode == IpoIbOnly  and it.SteeringTree.IpoIBType in SxpSteeringReq.IPoIBTypes);
			result = result and MeetSxLayersRequirements(SteeringNode, SxpSteeringReq);
		} else if SxpSteeringReq.PktType == IB{
			result = SteeringBranch.has(it.IsRoce == FALSE and it.IBSteeringMode == IbOnly);
			result = result and MeetSxLayersRequirements(SteeringNode, SxpSteeringReq);
		} else {
			result = SteeringBranch.has(it.IsRoce == FALSE);
			result = result and MeetSxLayersRequirements(SteeringNode, SxpSteeringReq);
		};
		if result {
			messagef(HIGH, "FlowGenerator.MeetSxRequirements: ") {
				SxpSteeringReq.PrintMe();
			};
		};
	};

	BuildSxpPktSteeringChanges(SxpSteeringReq : SxpGenSteeringReq ,SxpPktSteeringChanges : SxpGenSteeringChanges ) : bool is {
		var MeetRequirementsNodes : list of SteeringNode;
		for each (Tree) in UnicastFlowsList.all(it.Port == SxpSteeringReq.PortNumber) {
			MeetRequirementsNodes.add(Tree.GetAllChildren().all(it.Children.is_empty() and it.RssMode == None and it.LevelInTree != 0 and MeetSxRequirements(it, SxpSteeringReq)));
		};
		if MeetRequirementsNodes.is_empty() {
			return FALSE;
		};
		var ChosenEndNode : SteeringNode = MeetRequirementsNodes.RANDOM_ITEM();
		var SteeringBranch : list of SteeringNode = ChosenEndNode.GetSteeringBranch();
		SxpPktSteeringChanges.Gvmi = ChosenEndNode.SteeringTree.Gvmi;
		for each (node) in SteeringBranch{
			messagef(HIGH,"test"){
				node.PrintMe();
			};
		};
		if SxpSteeringReq.PktType == IB {
			SxpPktSteeringChanges.DestLID = SteeringBranch.first(it.Kind == Lid).FieldValue[111:96];
			SxpPktSteeringChanges.Lmc = SteeringBranch.first(it.Kind == Lid).Lmc;
			if SxpSteeringReq.HasGRH and SteeringBranch.has(it.Kind == Gid){ --  check with najeeb
				SxpPktSteeringChanges.DestGID = SteeringBranch.first(it.Kind == Gid).DGidList.RANDOM_ITEM();
			};
		};
		if SxpSteeringReq.PktType != IB or (SxpSteeringReq.PktType == IB and SxpSteeringReq.IPoIB){
			if SxpSteeringReq.PktType in [RoCE,RRoCE_IP,RRoCE_UDP] {
				SxpPktSteeringChanges.DestMac = SteeringBranch.first(it.Kind == Mac).FieldValue;
			} else if SxpSteeringReq.PktType != IB{
				SxpPktSteeringChanges.DestMac = SteeringBranch.first(it.Kind == Mac and not it.IsRoce).FieldValue;
			};
			if SteeringBranch.has(it.Kind == Vlan) {
				if SteeringBranch.has(it.Kind == Vlan and it.IsRoce == (SxpSteeringReq.PktType in [RoCE,RRoCE_IP,RRoCE_UDP])) {
					SxpPktSteeringChanges.VlanList = SteeringBranch.first(it.Kind == Vlan and it.IsRoce == (SxpSteeringReq.PktType in [RoCE,RRoCE_IP,RRoCE_UDP])).VlanList.copy();
				} else {
					return FALSE;
				};
			} else {
				SxpPktSteeringChanges.VlanList = {};
			};
			if SteeringBranch.has(it.Kind in [Ipv4_5Tuple,Ipv6L4,L4Only]) and SxpSteeringReq.L4Protocol not in [TCP,UDP] {
				return FALSE;
			};
			if SteeringBranch.has(it.Kind in [Ipv6Src,Ipv6Dst]) and SxpSteeringReq.L3EtherType != IPv6 {
				return FALSE;
			};
			if SteeringBranch.has(it.Kind in [Ipv4_5Tuple]) and SxpSteeringReq.L3EtherType != IPv4 {
				return FALSE;
			};

			if SxpSteeringReq.HasMPLS {
				SxpPktSteeringChanges.MplsLabel = SteeringBranch.first(it.Kind == Mpls).MplsLabelHeader.MPLSLabelStackList.copy();
			} else {
				SxpPktSteeringChanges.MplsLabel = {};
			};

			if SteeringBranch.SxSteeringModificationActions.SxModificationActionType.has(it in [Encapsulation,L3Encapsulation,PushVlan]) {
				for each (Node) in SteeringBranch.all(it.SxSteeringModificationActions.SxModificationActionType.has(it in [Encapsulation,L3Encapsulation,PushVlan])) {
					for each (SxModificationAction) in Node.SxSteeringModificationActions.all(it.SxModificationActionType in [Encapsulation,L3Encapsulation,PushVlan]) {
						case (SxModificationAction.SxModificationActionType) {
							Encapsulation : {
								SxpPktSteeringChanges.EncapPacket = deep_copy(Node.EncapsulationDataBase.Packet);
							};
							L3Encapsulation: {
								SxpPktSteeringChanges.L3EncapPacket = deep_copy(Node.EncapsulationDataBase.Packet);
							};
							PushVlan : {
								SxpPktSteeringChanges.VlanPushList.add(SxModificationAction.SxPushVlans);
								if SteeringBranch.all(it.SxSteeringModificationActions.SxModificationActionType.has(it  in [PushVlan])).count(TRUE) > 1 {
									SxpPktSteeringChanges.SecondVlanToPushAfterEncap = SxpPktSteeringChanges.FirstVlanToPushAfterEncap;
									SxpPktSteeringChanges.FirstVlanToPushAfterEncap  = SteeringBranch.has(it.SxSteeringModificationActions.SxModificationActionType.has(it in [Encapsulation,L3Encapsulation]) and it.LevelInTree < Node.LevelInTree);
								} else {
									SxpPktSteeringChanges.FirstVlanToPushAfterEncap  = SteeringBranch.has(it.SxSteeringModificationActions.SxModificationActionType.has(it in [Encapsulation,L3Encapsulation]) and it.LevelInTree < Node.LevelInTree);
								};
							};
						};
					};
				};
			};

			if SxpSteeringReq.PktType in [RoCE,RRoCE_IP,RRoCE_UDP] {
				return TRUE;
			};
			if SxpSteeringReq.L3EtherType == IPv4 {
				SxpPktSteeringChanges.DestIPv4   = SteeringBranch.first(it.Kind == Ipv4_5Tuple).FieldValue[127:96];
				SxpPktSteeringChanges.SourceIPv4 = SteeringBranch.first(it.Kind == Ipv4_5Tuple).FieldValue[95:64];
				SxpPktSteeringChanges.DestPort   = SteeringBranch.first(it.Kind == Ipv4_5Tuple).FieldValue[47:32];
				SxpPktSteeringChanges.SrcPort    = SteeringBranch.first(it.Kind == Ipv4_5Tuple).FieldValue[63:48];
				if SxpSteeringReq.L4Protocol not in [TCP,UDP] {
					return FALSE;
				};
			} else if SxpSteeringReq.L3EtherType == IPv6 {
				if SteeringBranch.has(it.Kind == Ipv6Dst) {
					SxpPktSteeringChanges.DestIPv6   = SteeringBranch.first(it.Kind == Ipv6Dst).FieldValue;
					SxpPktSteeringChanges.SteeringKind.add(Ipv6Dst);
				};
				if SteeringBranch.has(it.Kind == Ipv6Src) {
					SxpPktSteeringChanges.SourceIPv6 = SteeringBranch.first(it.Kind == Ipv6Src).FieldValue;
					SxpPktSteeringChanges.SteeringKind.add(Ipv6Src);
				};
				if SxpSteeringReq.L4Protocol in [TCP,UDP] {
					SxpPktSteeringChanges.DestPort   = SteeringBranch.first(it.Kind == Ipv6L4).FieldValue[111:96];
					SxpPktSteeringChanges.SrcPort    = SteeringBranch.first(it.Kind == Ipv6L4).FieldValue[79:64];
				};
			};
		};
		return TRUE;
	};

	GetAllowedNodeTypesFromEncapsulatedPacket(EncapsulatedNode : SteeringNode) : list of SteeringType is {
		result.add(EndOfTree);
		for each (Header) in EncapsulatedNode.EncapsulationDataBase.Packet.Headers {
			case Header.HeaderKind {
				[MAC] : {
					result.add(ENUMS_TO_LIST(MAC_STEERING_TYPE_WITH_DUMMY));
					result.add(ENUMS_TO_LIST(INNER_MAC_STEERING_TYPE_WITH_DUMMY));
				};
				[IPv4] : {
					result.add(ENUMS_TO_LIST(IPV4DST_STEERING_TYPE_WITH_DUMMY));
					result.add(ENUMS_TO_LIST(IPV4SRC_STEERING_TYPE_WITH_DUMMY));
					result.add(ENUMS_TO_LIST(INNER_IPV4DST_STEERING_TYPE_WITH_DUMMY));
					result.add(ENUMS_TO_LIST(INNER_IPV4SRC_STEERING_TYPE_WITH_DUMMY));
				};
				[IPv6] : {
					result.add(ENUMS_TO_LIST(IPV6DST_STEERING_TYPE_WITH_DUMMY));
					result.add(ENUMS_TO_LIST(IPV6SRC_STEERING_TYPE_WITH_DUMMY));
					result.add(ENUMS_TO_LIST(INNER_IPV6DST_STEERING_TYPE_WITH_DUMMY));
					result.add(ENUMS_TO_LIST(INNER_IPV6SRC_STEERING_TYPE_WITH_DUMMY));
				};
				[TCP,UDP] : {
					if EncapsulatedNode.EncapsulationDataBase.Packet.HasHeader(IPv6) {
						result.add(ENUMS_TO_LIST(IPV6L4_STEERING_TYPE_WITH_DUMMY));
						result.add(ENUMS_TO_LIST(INNER_IPV6L4_STEERING_TYPE_WITH_DUMMY));
					} else if EncapsulatedNode.EncapsulationDataBase.Packet.HasHeader(IPv4) {
						result.add(ENUMS_TO_LIST(IPV45TUPLE_STEERING_TYPE_WITH_DUMMY));
						result.add(ENUMS_TO_LIST(INNER_IPV45TUPLE_STEERING_TYPE_WITH_DUMMY));
					} else {
						DUTError(4401,"Encap Packet Has L4 Header with no IPv4/6 Header"){
							EncapsulatedNode.EncapsulationDataBase.Packet.PrintMe();
						};
					};
					result.add(ENUMS_TO_LIST(L4ONLY_STEERING_TYPE_WITH_DUMMY));
					result.add(ENUMS_TO_LIST(INNER_L4ONLY_STEERING_TYPE_WITH_DUMMY));
				};
			};
		};
		result.add({TunnelType;EndOfTree});
	};
};

extend MPLSLabelStack{
	AsAString() : string is {
		result = appendf("Label=%s, TrafficClass=%s, BottomOfStack=%s, TTL=%s",Label,TrafficClass,BottomOfStack,TTL);
	};
};

extend MacInternalHeader{
	PrintMe() is also{
		outf("%s\n", AsAString());
	};

	AsAString() : string is {
		result = appendf("EtherType=%s, PCP=%s, CFI_DEI=%s, VlanID=%s", EtherType, PCP, CFI_DEI, VlanID);
	};
};

extend SteeringParams{
	GetPrioFromIPSecEncapPacket(Port : uint) : uint(bits:3) is also {
		var EncapIPSecAction : SteeringNodeModificationActions = SxSteeringModificationActions.first(it.SxModificationActionType == InsertWithPointer and it.Attributes == push_esp);
		var EncapsulatedPacket : list of byte = EncapIPSecAction.DataToPush;
		var UnpackedEncapsulatedPacket : NetworkPacket = new;
		UnpackedEncapsulatedPacket.SetDontCheckOnUnpack();
		compute UnpackedEncapsulatedPacket.Unpack(EncapsulatedPacket, MAC, FALSE);
		var PacketPrio : uint(bits:3) = UnpackedEncapsulatedPacket.GetPrioForBufferQueueCalc(Port, Inbound); -- Remote->Local flow only, encap is added in Remote
		return PacketPrio;
	};

	GetPrioFromLastEncapAction(Port : uint, Direction: NetworkPacketDirection) : uint(bits:3) is also {
		var PrioSourceType : PrioSourceType;
		if Direction == Inbound {
			PrioSourceType = HANDLERS(Config).GetLogicalPortConfigInfoList().key(Port).PrioInfo.RxPrioSourceType;
		} else {
			PrioSourceType = HANDLERS(Config).GetLogicalPortConfigInfoList().key(Port).PrioInfo.SxPrioSourceType;
		};
		var LastEncapAction : SteeringNodeModificationActions = SxSteeringModificationActions.last(it.SxModificationActionType in [InsertWithPointer, L3Encapsulation, Encapsulation] and it.Attributes in [push_esp, encap_field_update] or (it.SxModificationActionType == PushVlan and PrioSourceType in [VlanDefault]) or (it.SxModificationActionType in [PushMpls] and PrioSourceType in [MplsExpDscpDefault]));

        if SxMacSecContext != NULL and (SxMacSecContext.SecTagMode == OverSrcAddr or PrioSourceType not in [VlanDefault]) {
            return  HANDLERS(Config).GetLogicalPortConfigInfoList().key(Port).PrioInfo.DefaultPrio
        };
		
		if LastEncapAction.SxModificationActionType == PushVlan {
			return LastEncapAction.SxPushVlans[0].PCP;
		};
		if LastEncapAction.SxModificationActionType == PushMpls {
			var ConfigRequirements = new with {
				.PortNum = Port
			};
			return HANDLERS(Config).Mpls2Prio(ConfigRequirements, LastEncapAction.MplsLabelsToPush[0].TrafficClass);
		};
		var EncapsulatedPacket : list of byte = LastEncapAction.DataToPush;
		var UnpackedEncapsulatedPacket : NetworkPacket = new;
		UnpackedEncapsulatedPacket.SetDontCheckOnUnpack();
		compute UnpackedEncapsulatedPacket.Unpack(EncapsulatedPacket, MAC, FALSE);
		var PacketPrio : uint(bits:3) = UnpackedEncapsulatedPacket.GetPrioForBufferQueueCalc(Port, Direction);
		return PacketPrio;
	};

	HasEncapActions(PortNum: uint, RemoteFlow : bool) : bool is also {
		result = SxSteeringModificationActions.SxModificationActionType.has(it in [Encapsulation, L3Encapsulation]);
		result = result or (SxSteeringInlineActions.SxInlineActionType.has(it == IpsecUnaware) and SxSaContext.IPSecMode in [Tunneled_IPv6, Tunneled_IPv4] and SxSaContext.IPSecHostType == Unaware);
		var PrioSourceType : PrioSourceType = HANDLERS(Config).GetLogicalPortConfigInfoList().key(PortNum).PrioInfo.RxPrioSourceType;
		if RemoteFlow {
			PrioSourceType = HANDLERS(Config).GetLogicalPortConfigInfoList().key(PortNum).PrioInfo.SxPrioSourceType
		};
		result = result or (SxSteeringModificationActions.SxModificationActionType.has(it in [PushVlan]) and PrioSourceType in [VlanDefault]);
		result = result or (SxSteeringModificationActions.SxModificationActionType.has(it in [PushMpls]) and PrioSourceType in [MplsExpDscpDefault]);
        result = result or (SxSteeringInlineActions.SxInlineActionType.has(it == MacsecUnaware) and (SxMacSecContext.SecTagMode == OverSrcAddr or PrioSourceType not in [VlanDefault]));
	};
	HasDecapPopEncapPushActions(SteeringSide) : bool is {
		if SteeringSide == Rx {
			result = RxSteeringModificationActions.RxModificationActionType.has(it in [DecapEnable, L3DecapEnable,PopVlan,PopMpls]);
		} else {
			result = RxSteeringModificationActions.RxModificationActionType.has(it in [Encapsulation, L3Encapsulation,PushVlan,PushMpls]);
		};
		result = result or (SxSteeringInlineActions.SxInlineActionType.has(it == IpsecUnaware) and SxSaContext.IPSecMode in [Tunneled_IPv6, Tunneled_IPv4] and SxSaContext.IPSecHostType == Unaware);
	};
	CanAddExtraVlans() : bool is also{
		return VlanValueType != NoValuesAllowed;
	};

	L4Required(): bool is {
		return RequiredSteeringList.has(it in [Ipv6L4, Ipv4_5Tuple, L4Only]) or (RxSteeringModificationActions.has(it.RxModificationActionType in [Add,Set,Copy] and not it.OnInnerPacket and it.RequiredHeader(it.RxModificationActionType).has(it in [TCP,UDP]))) or (RxSaContext != NULL and RxSaContext.AwareHost and EspMode==OverUdp and IPSecMode!=None);
	};

	TCPRequired(): bool is {
		return L4Required() and (L4Type == TCP or (TcpValueType == CertainValue or (RxSteeringModificationActions.has(it.RxModificationActionType in [Add,Set,Copy] and not it.OnInnerPacket and it.DstDwOffset in [OuterEthL4_Tcp]))));
	};

	TunnelingAllowedBySteering() : bool is also {
		if (RxSteeringModificationActions.has(it.RxModificationActionType in [Add,Set,Copy] and it.RequiredHeader(it.RxModificationActionType).has(it == TCP) and not it.RequiredHeader(it.RxModificationActionType).has(it == UDP))) {
			return FALSE;
		};
		if TCPRequired() {//RequiredSteeringList.has(it in [Ipv6L4,Ipv4_5Tuple,L4Only]) and TcpValueType == CertainValue {
			return FALSE;
		};
		if RequiredSteeringList.has(it in [Ipv6L4,Ipv4_5Tuple,L4Only]) and DestPortValueType==CertainValue and not NETWORK_PACKET_CONFIG.VXLAN_PORTList.has(it == DestPort) {
			return FALSE;
		};
        if SxSaContext != NULL and SxSaContext.IPSecHostType == Aware and SxSaContext.IPSecMode == Transport {
            return FALSE;
        };
		return TRUE;
	};

	PrintMe() is also {
		for each in RequiredSteeringList{
			case (it) {
				Mac : {
					outf("Mac = 0x%12x\n",Mac);
				};
				Vlan : {
					outf("Vlan:\n");
					for each (Vlan) in VlanList{
						Vlan.PrintMe();
						outf("\n");
					};
				};
				Mpls: {
					outf("Mpls: NumOfMpls - 0x%x\n", MplsLabelsList.size());
					for each (MPLSLabelStack) in MplsLabelsList {
						MPLSLabelStack.PrintMe();
						outf("\n");
					};
				};
				Ipv4Dst : {
					outf("Ipv4Dst = 0x%8x\n",Ipv4DestAddress);
				};
				Ipv4Src : {
					outf("Ipv4Src = 0x%8x\n",Ipv4SrcAddress);
				};
				Ipv6Dst : {
					outf("Ipv6Dst = 0x%32x\n",Ipv6DestAddress);
				};
				Ipv6Src : {
					outf("Ipv6Src = 0x%32x\n",Ipv6SrcAddress);
				};
				Ipv4_5Tuple : {
					outf("Ipv4 5 tuple: Ipv4DestAddress = 0x%8x Ipv4SrcAddress = 0x%8x DestPort = 0x%4x SourcePort = 0x%4x SourcePortValueType=%s DestPortValueType=%s TcpValueType=%s UdpValueType=%s \n",
						Ipv4DestAddress,Ipv4SrcAddress,DestPort,SourcePort, SourcePortValueType, DestPortValueType, TcpValueType, UdpValueType);
				};
				Ipv6L4 : {
					outf("Ipv6 L4 Dest Port = 0x%4x Source Port = 0x%4x SourcePortValueType=%s DestPortValueType=%s TcpValueType=%s UdpValueType=%s \n",DestPort,SourcePort,SourcePortValueType, DestPortValueType, TcpValueType, UdpValueType);
				};
				L4Only : {
					outf("L4 Dest Port = 0x%4x Source Port = 0x%4x SourcePortValueType=%s DestPortValueType=%s TcpValueType=%s UdpValueType=%s \n",DestPort,SourcePort,SourcePortValueType, DestPortValueType, TcpValueType, UdpValueType);
				};
				DestQp : {
					outf("Dest Qp %s is required\n",DestQp);
				};
				TunnelType : {
					outf("Tunnel Type 0x%8x is required network id = %s\n",SteeringTunnelType,L2TunnelingNetworkId);
				};
				Gid     : {
					for each (Gid) in DGidList {
						outf("\nDGid = %s\n",Gid);
					};
				};
				Lid     : {
					outf("Lid = %s\n",DLid);
				};
			};
		};
		if not EncapsulatedPacket.is_empty() {
			var TempPkt: NetworkPacket = new;
			TempPkt.DontUnpackTrailer = TRUE;
			compute TempPkt.Unpack(EncapsulatedPacket, MAC, FALSE);
			outf( "EncapsulatedPacket: \n");
			TempPkt.MACHeader().HasFCS = FALSE;
			TempPkt.PrintMe();
		};
		if InnerSteeringParams != NULL{
			outf("Inner Steering Params:\n");
			InnerSteeringParams.PrintMe();
		};
	};

	CanReceivePacket(Pkt: NetworkPacket): bool is {
		result = TRUE;
		for each in RequiredSteeringList{
			case (it) {
				Mac : {
					if Mac != Pkt.MACHeader().DestAddr {
						return FALSE;
					};
				};
				Vlan : {
					if Pkt.MACHeader().MacInternalHeaders.size() < VlanList.size() {
						return FALSE;
					};
					for each (Vlan) in VlanList{
						if (Vlan.PCP != Pkt.MACHeader().MacInternalHeaders[index].PCP or
								Vlan.CFI_DEI != Pkt.MACHeader().MacInternalHeaders[index].CFI_DEI or
								Vlan.VlanID != Pkt.MACHeader().MacInternalHeaders[index].VlanID or
								Vlan.EtherType != Pkt.MACHeader().MacInternalHeaders[index].EtherType) {
							return FALSE;
						};
					};
				};
				Ipv6Dst : {
					if !Pkt.HasHeader(IPv6) or Pkt.IPv6Header().DestGID != Ipv6DestAddress {
						return FALSE;
					};
				};
				Ipv6Src : {
					if !Pkt.HasHeader(IPv6) or Pkt.IPv6Header().SrcGID != Ipv6SrcAddress {
						return FALSE;
					};
				};
				Ipv4_5Tuple : {
					if !Pkt.HasHeader(IPv4) or Pkt.IPv4Header().DestAddress != Ipv4DestAddress {
						return FALSE;
					};
					if !Pkt.HasHeader(IPv4) or Pkt.IPv4Header().SrcAddress != Ipv4SrcAddress {
						return FALSE;
					};
					if (!Pkt.HasHeader(UDP) and !Pkt.HasHeader(TCP) or
							Pkt.HasHeader(UDP) and (Pkt.UDPHeader().SrcPort != SourcePort or Pkt.UDPHeader().DestPort != DestPort) or
							Pkt.HasHeader(TCP) and (Pkt.TCPHeader().SrcPort != SourcePort or Pkt.TCPHeader().DestPort != DestPort)) {
						return FALSE;
					};
				};
				Ipv6L4 : {
					if (!Pkt.HasHeader(IPv6) or !Pkt.HasHeader(UDP) and !Pkt.HasHeader(TCP) or
							Pkt.HasHeader(UDP) and (Pkt.UDPHeader().SrcPort != SourcePort or Pkt.UDPHeader().DestPort != DestPort) or
							Pkt.HasHeader(TCP) and (Pkt.TCPHeader().SrcPort != SourcePort or Pkt.TCPHeader().DestPort != DestPort)) {
						return FALSE;
					};
				};
				DestQp : {
					continue;
				};
				TunnelType : {
					var NodeTunnelType : TunnelType = SteeringTunnelType in [GRE,NVGRE] ? GRE : (SteeringTunnelType == VXLAN ? VXLAN : (SteeringTunnelType == FlexParsing ? FlexParsing : None));
					if Pkt.TunnelType != NodeTunnelType or Pkt.GetTunnelKey() != L2TunnelingNetworkId {
						return FALSE;
					};
				};
			};
		};
	};
};

extend NetworkPacket {
	GetTunnelKey(): uint is {
		var L2TunnelingNetworkId : uint(bits : 32);
		case TunnelType {
			VXLAN: {
				L2TunnelingNetworkId[31:8] = VXLANHeader().VNI;
				L2TunnelingNetworkId[7:0]  = VXLANHeader().Reserved2;
			};
			GRE: {
				if GREHeader().GREType != NVGRE {
					L2TunnelingNetworkId = GREHeader().Key;
				} else { //nvgre
					L2TunnelingNetworkId[31:8] = GREHeader().VSID;
					L2TunnelingNetworkId[7:0]  = GREHeader().FlowID;
				};
			};
		};
		return L2TunnelingNetworkId;
	};
};
'>
