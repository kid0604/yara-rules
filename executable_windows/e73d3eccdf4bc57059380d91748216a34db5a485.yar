import "pe"

rule UPXModifiedStubcFarbrauschConsumerConsulting
{
	meta:
		author = "malware-lu"
		description = "Detects a modified UPX stub used by the cFarbrausch Consumer Consulting malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 BE [4] 8D BE [4] 57 83 CD FF FC B2 80 E8 00 00 00 00 5B 83 C3 66 A4 FF D3 73 FB 31 C9 FF D3 73 14 31 C0 FF D3 73 1D 41 B0 10 FF D3 10 C0 73 FA 75 3C AA EB E2 E8 4A 00 00 00 49 E2 10 E8 40 00 00 00 EB 28 AC D1 E8 74 45 11 C9 EB 1C 91 48 }

	condition:
		$a0 at pe.entry_point
}
