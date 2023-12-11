import "pe"

rule CrinklerV01V02RuneLHStubbeandAskeSimonChristensen
{
	meta:
		author = "malware-lu"
		description = "Detects Crinkler V01/V02 Rune LH Stubbe and Aske Simon Christensen malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B9 [4] 01 C0 68 [4] 6A 00 58 50 6A 00 5F 48 5D BB 03 00 00 00 BE [4] E9 }

	condition:
		$a0 at pe.entry_point
}
