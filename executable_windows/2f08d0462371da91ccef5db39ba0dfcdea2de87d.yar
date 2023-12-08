import "pe"

rule ExeSplitter13SplitCryptMethodBillPrisonerTPOC
{
	meta:
		author = "malware-lu"
		description = "Detects the ExeSplitter13SplitCryptMethodBillPrisonerTPOC malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 15 10 05 23 14 56 57 57 48 12 0B 16 66 66 66 66 66 66 66 66 66 02 C7 56 66 66 66 ED 26 6A ED 26 6A ED 66 E3 A6 69 E2 39 64 66 66 ED 2E 56 E6 5F 0D 12 61 E6 5F 2D 12 64 8D 81 E6 1F 6A 55 12 64 8D B9 ED 26 7E A5 33 ED 8A 8D 69 21 03 12 36 14 09 05 27 02 02 14 03 15 15 27 ED 2B 6A ED 13 6E ED B8 65 10 5A EB 10 7E EB 10 06 ED 50 65 95 30 ED 10 46 65 95 55 B4 ED A0 ED 50 65 95 37 ED 2B 6A EB DF AB 76 26 66 3F DF 68 66 66 66 9A 95 C0 6D AF 13 64 }
		$a1 = { E8 00 00 00 00 5D 81 ED 05 10 40 00 B9 [4] 8D 85 1D 10 40 00 80 30 66 40 E2 FA 8F 98 67 66 66 [7] 66 }

	condition:
		$a0 or $a1 at pe.entry_point
}
