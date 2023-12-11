import "pe"

rule EEXEVersion112
{
	meta:
		author = "malware-lu"
		description = "Detects a specific version of EEXE malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B4 30 CD 21 3C 03 73 ?? BA 1F 00 0E 1F B4 09 CD 21 B8 FF 4C CD 21 }

	condition:
		$a0 at pe.entry_point
}
