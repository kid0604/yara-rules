import "pe"

rule EXECryptorV21Xsoftcompletecom
{
	meta:
		author = "malware-lu"
		description = "Detects EXECryptorV2.1Xsoftcompletecom malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 C6 14 8B 55 FC E9 ?? FF FF FF }
		$a1 = { E9 [4] 66 9C 60 50 8D 88 [4] 8D 90 04 16 [2] 8B DC 8B E1 }

	condition:
		$a0 or $a1 at pe.entry_point
}
