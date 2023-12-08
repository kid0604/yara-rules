import "pe"

rule EXEjoinerAmok
{
	meta:
		author = "malware-lu"
		description = "Detects the EXEjoinerAmok malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { A1 14 A1 40 00 C1 E0 02 A3 18 A1 40 }

	condition:
		$a0 at pe.entry_point
}
