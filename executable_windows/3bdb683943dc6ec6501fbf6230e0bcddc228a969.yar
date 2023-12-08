import "pe"

rule PellesC300400450EXEX86CRTDLL
{
	meta:
		author = "malware-lu"
		description = "Detects Pelles C 300, 400, 450 EXE X86 CRT DLL"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 6A FF 68 [4] 68 [4] 64 FF 35 [4] 64 89 25 [4] 83 EC ?? 53 56 57 89 65 E8 C7 45 FC [4] 68 [4] E8 [4] 59 BE [4] EB }

	condition:
		$a0 at pe.entry_point
}
