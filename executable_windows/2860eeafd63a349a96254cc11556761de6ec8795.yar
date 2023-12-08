import "pe"

rule UPXShitv01500mhz
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of UPX packed files with specific characteristics"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 [2] 00 [3] 00 [3] 01 [3] 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79 }
		$a1 = { E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 [2] 00 [3] 00 [7] 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79 }
		$a2 = { E8 [4] 5E 83 C6 ?? AD 89 C7 AD 89 C1 AD 30 07 47 E2 ?? AD FF E0 C3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}
