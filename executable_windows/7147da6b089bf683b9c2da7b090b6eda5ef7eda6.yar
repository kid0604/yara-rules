import "pe"

rule W32JeefoPEFileInfector
{
	meta:
		author = "malware-lu"
		description = "Detects W32 Jeefo PE file infector"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 83 EC 08 83 C4 F4 6A 02 A1 C8 [3] FF D0 E8 [4] C9 C3 }

	condition:
		$a0 at pe.entry_point
}
