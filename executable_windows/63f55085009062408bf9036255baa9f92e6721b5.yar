import "pe"

rule Upxv12MarcusLazlo
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the Upxv12MarcusLazlo malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 BE [4] 8D BE [4] 57 83 CD FF EB 05 A4 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 F2 31 C0 40 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 E6 31 C9 83 }

	condition:
		$a0 at pe.entry_point
}
