import "pe"

rule Disclosed_0day_POCs_injector
{
	meta:
		description = "Detects POC code from disclosed 0day hacktool set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed 0day Repos"
		date = "2017-07-07"
		hash1 = "ba0e2119b2a6bad612e86662b643a404426a07444d476472a71452b7e9f94041"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\Release\\injector.pdb" ascii
		$x2 = "Cannot write the shellcode in the process memory, error: " fullword ascii
		$x3 = "/s shellcode_file PID: shellcode injection." fullword ascii
		$x4 = "/d dll_file PID: dll injection via LoadLibrary()." fullword ascii
		$x5 = "/s shellcode_file PID" fullword ascii
		$x6 = "Shellcode copied in memory: OK" fullword ascii
		$x7 = "Usage of the injector. " fullword ascii
		$x8 = "KO: cannot obtain the SeDebug privilege." fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <90KB and 1 of them ) or 3 of them
}
