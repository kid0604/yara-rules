import "pe"

rule PellesC300400450EXEX86CRTLIB
{
	meta:
		author = "malware-lu"
		description = "Detects Pelles C 300, 400, or 450 EXE X86 CRT library"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 6A FF 68 [4] 68 [4] 64 FF 35 [4] 64 89 25 [4] 83 EC ?? 53 56 57 89 65 E8 68 00 00 00 02 E8 [4] 59 A3 }

	condition:
		$a0 at pe.entry_point
}
