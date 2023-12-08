import "pe"

rule PEtitev20
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of PEtitev20 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [4] 66 9C 60 50 8B D8 03 ?? 68 54 BC [2] 6A ?? FF 50 18 8B CC 8D A0 54 BC [2] 8B C3 8D 90 E0 15 [2] 68 }

	condition:
		$a0 at pe.entry_point
}
