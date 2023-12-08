rule Exploit_MS15_077_078_HackingTeam_alt_1
{
	meta:
		description = "MS15-078 / MS15-077 exploit - Hacking Team code"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015-07-21"
		super_rule = 1
		hash1 = "ad6bb982a1ecfe080baf0a2b27950f989c107949b1cf02b6e0907f1a568ece15"
		hash2 = "fc609adef44b5c64de029b2b2cff22a6f36b6bdf9463c1bd320a522ed39de5d9"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\SystemRoot\\system32\\CI.dll" ascii
		$s2 = "\\sysnative\\CI.dll" ascii
		$s3 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 Safari/537.36" fullword ascii
		$s4 = "CRTDLL.DLL" fullword ascii
		$s5 = "\\sysnative" ascii
		$s6 = "InternetOpenA coolio, trying open %s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2500KB and 5 of them
}
