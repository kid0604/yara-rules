rule CN_Honker_no_net_priv_esc_AddUser
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file AddUser.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "4c95046be6ae40aee69a433e9a47f824598db2d4"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "PECompact2" fullword ascii
		$s1 = "adduser" fullword ascii
		$s5 = "OagaBoxA" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <115KB and all of them
}
