import "pe"

rule VxAugust16thIronMaiden
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of VxAugust16thIronMaiden malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BA 79 02 03 D7 B4 1A CD 21 B8 24 35 CD 21 5F 57 89 9D 4E 02 8C 85 50 02 }

	condition:
		$a0 at pe.entry_point
}
