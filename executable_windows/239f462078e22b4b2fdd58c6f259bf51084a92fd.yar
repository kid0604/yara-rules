rule SFXRAR_Acrotray
{
	meta:
		description = "Most likely a malicious file acrotray in SFX RAR / CloudDuke APT 5442.1.exe, 5442.2.exe"
		author = "Florian Roth"
		reference = "https://www.f-secure.com/weblog/archives/00002822.html"
		date = "2015-07-22"
		super_rule = 1
		score = 70
		hash1 = "51e713c7247f978f5836133dd0b8f9fb229e6594763adda59951556e1df5ee57"
		hash2 = "5d695ff02202808805da942e484caa7c1dc68e6d9c3d77dc383cfa0617e61e48"
		hash3 = "56531cc133e7a760b238aadc5b7a622cd11c835a3e6b78079d825d417fb02198"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "winrarsfxmappingfile.tmp" fullword wide
		$s2 = "GETPASSWORD1" fullword wide
		$s3 = "acrotray.exe" fullword ascii
		$s4 = "CryptUnprotectMemory failed" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <2449KB and all of them
}
