import "pe"

rule PellesC2x4xDLLPelleOrinius
{
	meta:
		author = "malware-lu"
		description = "Detects Pelles C 2x4x DLL Pelle Orinius malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 }

	condition:
		$a0 at pe.entry_point
}
