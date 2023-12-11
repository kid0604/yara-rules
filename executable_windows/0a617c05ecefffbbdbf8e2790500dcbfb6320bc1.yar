import "pe"

rule APT_HiddenCobra_GhostSecret_1
{
	meta:
		description = "Detects Hidden Cobra Sample"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/"
		date = "2018-08-11"
		hash1 = "05a567fe3f7c22a0ef78cc39dcf2d9ff283580c82bdbe880af9549e7014becfc"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%s\\%s.dll" fullword wide
		$s2 = "PROXY_SVC_DLL.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and all of them
}
