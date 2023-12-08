rule CN_Honker_GetHashes
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GetHashes.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "dc8bcebf565ffffda0df24a77e28af681227b7fe"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "SAM\\Domains\\Account\\Users\\Names registry hive reading error!" fullword ascii
		$s1 = "GetHashes <SAM registry file> [System key file]" fullword ascii
		$s2 = "Note: Windows registry file shall begin from 'regf' signature!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <87KB and 2 of them
}
