rule EquationGroup_Toolset_Apr17_Easypi_Explodingcan
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "dc1ddad7e8801b5e37748ec40531a105ba359654ffe8bdb069bd29fb0b5afd94"
		hash2 = "97af543cf1fb59d21ba5ec6cb2f88c8c79c835f19c8f659057d2f58c321a0ad4"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "[-] %s - Target might not be in a usable state." fullword ascii
		$x2 = "[*] Exploiting Target" fullword ascii
		$x3 = "[-] Encoding Exploit Payload failed!" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 1 of them )
}
