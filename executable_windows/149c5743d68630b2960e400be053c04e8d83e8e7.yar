rule CN_Honker_net_packet_capt
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file net_packet_capt.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "2d45a2bd9e74cf14c1d93fff90c2b0665f109c52"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "(*.sfd)" fullword ascii
		$s2 = "GetLaBA" fullword ascii
		$s3 = "GAIsProcessorFeature" fullword ascii
		$s4 = "- Gablto " ascii
		$s5 = "PaneWyedit" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <50KB and all of them
}
