import "pe"

rule PellesC450DLLX86CRTLIB
{
	meta:
		author = "malware-lu"
		description = "Detects Pelles C 4.50 DLL X86 CRT library"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 85 DB 75 0D 83 3D [4] 00 75 04 31 C0 EB 57 83 FB 01 74 05 83 FB 02 75 }

	condition:
		$a0 at pe.entry_point
}
