rule CN_Honker_Happy_Happy
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Happy.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		modified = "2023-01-27"
		score = 70
		hash = "92067d8dad33177b5d6c853d4d0e897f2ee846b0"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "<form.*?method=\"post\"[\\s\\S]*?</form>" fullword wide
		$s2 = "domainscan.exe" fullword wide
		$s3 = "http://www.happysec.com/" wide
		$s4 = "cmdshell" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <655KB and 2 of them
}
