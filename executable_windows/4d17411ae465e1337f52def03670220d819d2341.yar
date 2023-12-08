rule LightFTP_fftp_x86_64
{
	meta:
		description = "Detects a light FTP server"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/hfiref0x/LightFTP"
		date = "2015-05-14"
		hash1 = "989525f85abef05581ccab673e81df3f5d50be36"
		hash2 = "5884aeca33429830b39eba6d3ddb00680037faf4"
		score = 50
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "fftp.cfg" fullword wide
		$s2 = "220 LightFTP server v1.0 ready" fullword ascii
		$s3 = "*FTP thread exit*" fullword wide
		$s4 = "PASS->logon successful" fullword ascii
		$s5 = "250 Requested file action okay, completed." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <250KB and 4 of them
}
