rule EquationGroup_Toolset_Apr17_rc5
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		hash1 = "69e2c68c6ea7be338497863c0c5ab5c77d5f522f0a84ab20fe9c75c7f81318eb"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Usage: %s [d|e] session_key ciphertext" fullword ascii
		$s2 = "where session_key and ciphertext are strings of hex" fullword ascii
		$s3 = "d = decrypt mode, e = encrypt mode" fullword ascii
		$s4 = "Bad mode, should be 'd' or 'e'" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and 2 of them )
}
