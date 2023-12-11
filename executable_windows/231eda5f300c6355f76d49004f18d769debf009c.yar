rule Kriskynote_Mar17_3
{
	meta:
		description = "Detects Kriskynote Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-03-03"
		hash1 = "fc838e07834994f25b3b271611e1014b3593278f0703a4a985fb4234936df492"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "rundll32 %s Check" fullword ascii
		$s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs" fullword ascii
		$s3 = "name=\"IsUserAdmin\"" fullword ascii
		$s4 = "zok]\\\\\\ZZYYY666564444" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 2 of them )
}
