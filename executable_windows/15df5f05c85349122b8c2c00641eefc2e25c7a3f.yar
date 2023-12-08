import "pe"

rule PellesC290300400DLLX86CRTLIB
{
	meta:
		author = "malware-lu"
		description = "Detects Pelles C 2.9.0.400 DLL X86 CRT library"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 BF 01 00 00 00 85 DB 75 10 83 3D [4] 00 75 07 31 C0 E9 [4] 83 FB 01 74 05 83 FB 02 75 ?? 85 FF 74 }

	condition:
		$a0 at pe.entry_point
}
