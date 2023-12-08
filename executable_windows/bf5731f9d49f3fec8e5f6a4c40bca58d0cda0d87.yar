import "pe"

rule VxDanishtiny
{
	meta:
		author = "malware-lu"
		description = "Detects the VxDanishtiny malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 33 C9 B4 4E CD 21 73 02 FF ?? BA ?? 00 B8 ?? 3D CD 21 }

	condition:
		$a0 at pe.entry_point
}
