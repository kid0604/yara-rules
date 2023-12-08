rule Codoso_PlugX_1
{
	meta:
		description = "Detects Codoso APT PlugX Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		super_rule = 1
		hash1 = "0b8cbc9b4761ab35acce2aa12ba2c0a283afd596b565705514fd802c8b1e144b"
		hash2 = "448711bd3f689ceebb736d25253233ac244d48cb766834b8f974c2e9d4b462e8"
		hash3 = "fd22547497ce52049083092429eeff0599d0b11fe61186e91c91e1f76b518fe2"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "GETPASSWORD1" fullword ascii
		$s2 = "NvSmartMax.dll" fullword ascii
		$s3 = "LICENSEDLG" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <800KB and all of them
}
