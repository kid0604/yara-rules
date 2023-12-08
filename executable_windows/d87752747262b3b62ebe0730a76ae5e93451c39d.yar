import "pe"

rule APT_Thrip_Sample_Jun18_10
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		date = "2018-06-21"
		hash1 = "350d2a6f8e6a4969ffbf75d9f9aae99e7b3a8cd8708fd66f977e07d7fbf842e3"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "!This Program cannot be run in DOS mode." fullword ascii
		$x2 = "!this program cannot be run in dos mode." fullword ascii
		$s1 = "svchost.dll" fullword ascii
		$s2 = "constructor or from DllMain." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and ($x1 or 2 of them )
}
