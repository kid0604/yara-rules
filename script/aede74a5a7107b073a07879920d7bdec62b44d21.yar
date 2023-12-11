rule FVEY_ShadowBroker_user_tool_elgingamble
{
	meta:
		description = "Auto-generated rule - file user.tool.elgingamble.COMMON"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		date = "2016-12-17"
		hash1 = "4130284727ddef4610d63bfa8330cdafcb6524d3d2e7e8e0cb34fde8864c8118"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x2 = "### Local exploit for" fullword ascii

	condition:
		1 of them
}
