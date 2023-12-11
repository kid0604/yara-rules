import "pe"

rule UPXFreakv01BorlandDelphiHMX0101
{
	meta:
		author = "malware-lu"
		description = "Detects Borland Delphi UPX Freak HMX0101 packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE [4] 83 C6 01 FF E6 00 00 00 [3] 00 03 00 00 00 [4] 00 10 00 00 00 00 [4] 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 [3] 00 [3] 00 [3] 00 ?? 24 ?? 00 [3] 00 }
		$a1 = { BE [4] 83 C6 01 FF E6 00 00 00 [3] 00 03 00 00 00 [4] 00 10 00 00 00 00 [4] 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 [3] 00 [3] 00 [3] 00 ?? 24 ?? 00 [3] 00 34 50 45 00 [3] 00 FF FF 00 00 ?? 24 ?? 00 ?? 24 ?? 00 [3] 00 40 00 00 C0 00 00 [4] 00 00 ?? 00 00 00 ?? 1E ?? 00 ?? F7 ?? 00 A6 4E 43 00 ?? 56 ?? 00 AD D1 42 00 ?? F7 ?? 00 A1 D2 42 00 ?? 56 ?? 00 0B 4D 43 00 ?? F7 ?? 00 ?? F7 ?? 00 ?? 56 ?? 00 [5] 00 00 00 [7] 77 [3] 00 [3] 00 [3] 77 [2] 00 00 [3] 00 [6] 00 00 [3] 00 [11] 00 [4] 00 00 00 00 [3] 00 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
