import "pe"

rule CrinklerV03V04RuneLHStubbeandAskeSimonChristensen
{
	meta:
		author = "malware-lu"
		description = "Detects Crinkler V03/V04 Rune LH Stubbe and Aske Simon Christensen malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 00 00 42 00 31 DB 43 EB 58 }

	condition:
		$a0 at pe.entry_point
}
