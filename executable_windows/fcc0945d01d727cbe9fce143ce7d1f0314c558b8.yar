import "pe"

rule MALWARE_Win_DEADWOOD
{
	meta:
		author = "ditekSHen"
		description = "Detects DEADWOOD"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Service Start Work !!!!" fullword ascii
		$s2 = "Error GetTokenInformation : " fullword ascii
		$s3 = "\\Windows\\System32\\net.exe" fullword wide
		$s4 = "App Start Work !!!!" fullword ascii
		$s5 = "vmmouse" fullword wide
		$s6 = "CDPUserSvc_" wide
		$s7 = "WpnUserService_" wide
		$s8 = "User is :" wide
		$s9 = "\\params" fullword ascii

	condition:
		uint16(0)==0x5a4d and 6 of them
}
