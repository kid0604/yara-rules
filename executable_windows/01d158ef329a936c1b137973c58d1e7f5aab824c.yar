import "pe"

rule hyingsPEArmorV076hying
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the PE Armor V076hying malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A ?? E8 A3 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
