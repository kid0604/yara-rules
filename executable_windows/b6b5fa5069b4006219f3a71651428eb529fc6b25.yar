rule APT_Malware_CommentCrew_MiniASP
{
	meta:
		description = "CommentCrew Malware MiniASP APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VT Analysis"
		date = "2015-06-03"
		super_rule = 1
		hash0 = "0af4360a5ae54d789a8814bf7791d5c77136d625"
		hash1 = "777bf8def279942a25750feffc11d8a36cc0acf9"
		hash2 = "173f20b126cb57fc8ab04d01ae223071e2345f97"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\MiniAsp4\\Release\\MiniAsp.pdb" ascii
		$x2 = "run http://%s/logo.png setup.exe" fullword ascii
		$x3 = "d:\\command.txt" fullword ascii
		$z1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR " ascii
		$z2 = "Mozilla/4.0 (compatible; MSIE 7.4; Win32;32-bit)" fullword ascii
		$z3 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC" ascii
		$s1 = "http://%s/device_command.asp?device_id=%s&cv=%s&command=%s" fullword ascii
		$s2 = "kill process error!" fullword ascii
		$s3 = "kill process success!" fullword ascii
		$s4 = "pickup command error!" fullword ascii
		$s5 = "http://%s/record.asp?device_t=%s&key=%s&device_id=%s&cv=%s&result=%s" fullword ascii
		$s6 = "no command" fullword ascii
		$s7 = "software\\microsoft\\windows\\currentversion\\run" fullword ascii
		$s8 = "command is null!" fullword ascii
		$s9 = "pickup command Ok!" fullword ascii
		$s10 = "http://%s/result_%s.htm" fullword ascii

	condition:
		uint16(0)==0x5a4d and (1 of ($x*)) or ( all of ($z*)) or (8 of ($s*))
}
