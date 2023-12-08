rule CN_Honker_InvasionErasor
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file InvasionErasor.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b37ecd9ee6b137a29c9b9d2801473a521b168794"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "c:\\windows\\system32\\config\\*.*" fullword wide
		$s2 = "c:\\winnt\\*.txt" fullword wide
		$s3 = "Command1" fullword ascii
		$s4 = "Win2003" fullword ascii
		$s5 = "Win 2000" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <60KB and all of them
}
