rule CN_Honker_Oracle_v1_0_Oracle
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Oracle.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0264f4efdba09eaf1e681220ba96de8498ab3580"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "!http://localhost/index.asp?id=zhr" fullword ascii
		$s2 = "OnGetPassword" fullword ascii
		$s3 = "Mozilla/3.0 (compatible; Indy Library)" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3455KB and all of them
}
