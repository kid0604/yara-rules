rule Ransom_Locky
{
	meta:
		description = "Detect the risk of Ransomware Locky Rule 1"
		hash1 = "5606e9dc4ab113749953687adac6ddb7b19c864f6431bdcf0c5b0e2a98cca39e"
		hash2 = "8ff979f23f8bab94ce767d4760811bde66c556c0c56b72bb839d4d277b3703ad"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "gefas.pdb" fullword ascii
		$s2 = "ggqfslmb" fullword ascii
		$s3 = "gr7shadtasghdj" fullword ascii
		$s4 = "ppgnui.dll" fullword ascii
		$s5 = "unqxfddunlkl" fullword ascii
		$s6 = "hpmeiokm" fullword ascii
		$s7 = "bdkc" fullword ascii
		$s8 = {47 41 41 00 63 65 73 73 68 3B 41 41 00 82 04 24}
		$s9 = {41 00 68 77 41 41 00 E8}
		$s10 = "sctrs.dll" fullword ascii
		$s11 = {61 8D 35 2E 41 41}
		$pack = {00 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 E0 2E 64 65 63 00 00 00 00 00 00}

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 2 of them
}
