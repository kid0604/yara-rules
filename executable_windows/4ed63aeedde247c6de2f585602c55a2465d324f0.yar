import "pe"

rule PEtitev14
{
	meta:
		author = "malware-lu"
		description = "Detects the PEtitev14 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 66 9C 60 50 8B D8 03 ?? 68 54 BC [2] 6A ?? FF 50 14 8B CC }
		$a1 = { 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
