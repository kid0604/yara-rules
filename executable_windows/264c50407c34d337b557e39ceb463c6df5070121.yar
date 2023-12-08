import "pe"

rule ChSfxsmallv11
{
	meta:
		author = "malware-lu"
		description = "Detects a small self-extracting executable"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BA [2] E8 [2] 8B EC 83 EC ?? 8C C8 BB [2] B1 ?? D3 EB 03 C3 8E D8 05 [2] 89 }

	condition:
		$a0 at pe.entry_point
}
