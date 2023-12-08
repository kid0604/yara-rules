rule Unspecified_Malware_Oct16_A
{
	meta:
		description = "Detects an unspecififed malware - October 2016"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2016-10-08"
		score = 80
		hash1 = "d112a7e21902287e4a37112bf17d7c73a7b206e7bc81780fd87991c1519f38c8"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "%s\\system32\\%s.dll" fullword ascii
		$x2 = "%SystemRoot%\\System32\\svch%s -k nets" fullword ascii
		$x3 = "\\\\.\\pipe\\96DBA249-E88E-4c47-98DC-E18E6E3E3E5A" fullword ascii
		$s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" fullword ascii
		$s2 = "boottemp.exe" fullword ascii
		$s3 = "at \\\\%s %d:%d C:\\%s.exe" fullword ascii
		$s4 = "cryptcom.dll" fullword ascii
		$s5 = "Wininet.dll" fullword ascii
		$s6 = "\\\\%s\\%s\\%s.exe" fullword ascii
		$s7 = "%s%d.exe" fullword ascii
		$s8 = "booter.exe" fullword ascii
		$s9 = "\\\\%s\\pipe%s" fullword ascii
		$s10 = "C:\\DelInfo.bin" fullword ascii
		$op0 = { ae 44 00 00 cb 44 00 00 dc 44 00 00 f5 44 00 00 }
		$op1 = { ae 44 00 00 cb 44 00 00 dc 44 00 00 f5 44 00 00 }
		$op2 = { ee 11 74 cf 73 0b 91 c4 c9 57 b2 d9 36 86 a5 b4 }

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and (2 of ($x*) or 3 of ($s*) or all of ($op*))) or (6 of them )
}
