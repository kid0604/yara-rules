import "pe"

rule WinUpackv030betaByDwing
{
	meta:
		author = "malware-lu"
		description = "Detects the WinUpack v3.0 beta by Dwing packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 [4] 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 }
		$a1 = { E9 [4] 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 }

	condition:
		$a0 or $a1
}
