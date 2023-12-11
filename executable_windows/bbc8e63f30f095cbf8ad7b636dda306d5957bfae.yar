import "pe"

rule UPXModifiedStubbFarbrauschConsumerConsulting
{
	meta:
		author = "malware-lu"
		description = "Detects a modified UPX stub used by the Farbrausch Consumer Consulting malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 BE [4] 8D BE [4] 57 83 CD FF FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC }

	condition:
		$a0 at pe.entry_point
}
