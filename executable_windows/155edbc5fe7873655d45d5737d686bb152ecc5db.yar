import "pe"

rule Kekeo_Hacktool
{
	meta:
		description = "Detects Kekeo Hacktool"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/gentilkiwi/kekeo/releases"
		date = "2017-07-21"
		hash1 = "ce92c0bcdf63347d84824a02b7a448cf49dd9f44db2d02722d01c72556a2b767"
		hash2 = "49d7fec5feff20b3b57b26faccd50bc05c71f1dddf5800eb4abaca14b83bba8c"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "[ticket %u] session Key is NULL, maybe a TGT without enough rights when WCE dumped it." fullword wide
		$x2 = "ERROR kuhl_m_smb_time ; Invalid! Command: %02x - Status: %08x" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and (1 of ($x*)))
}
