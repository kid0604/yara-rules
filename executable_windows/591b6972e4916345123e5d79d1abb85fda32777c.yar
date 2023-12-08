rule network_p2p_win
{
	meta:
		author = "x0r"
		description = "Communications over P2P network"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$c1 = "PeerCollabExportContact"
		$c2 = "PeerCollabGetApplicationRegistrationInfo"
		$c3 = "PeerCollabGetEndpointName"
		$c4 = "PeerCollabGetEventData"
		$c5 = "PeerCollabGetInvitationResponse"
		$c6 = "PeerCollabGetPresenceInfo"
		$c7 = "PeerCollabGetSigninOptions"
		$c8 = "PeerCollabInviteContact"
		$c9 = "PeerCollabInviteEndpoint"
		$c10 = "PeerCollabParseContact"
		$c11 = "PeerCollabQueryContactData"
		$c12 = "PeerCollabRefreshEndpointData"
		$c13 = "PeerCollabRegisterApplication"
		$c14 = "PeerCollabRegisterEvent"
		$c15 = "PeerCollabSetEndpointName"
		$c16 = "PeerCollabSetObject"
		$c17 = "PeerCollabSetPresenceInfo"
		$c18 = "PeerCollabSignout"
		$c19 = "PeerCollabUnregisterApplication"
		$c20 = "PeerCollabUpdateContact"

	condition:
		5 of them
}
