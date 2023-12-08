import "pe"

rule VxTrivial46
{
	meta:
		author = "malware-lu"
		description = "Detects VxTrivial46 malware based on specific byte sequences at the entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B4 4E B1 20 BA [2] CD 21 BA [2] B8 ?? 3D CD 21 }

	condition:
		$a0 at pe.entry_point
}
