import "pe"

rule CodeLockvxx
{
	meta:
		author = "malware-lu"
		description = "Detects CodeLockvxx malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 }

	condition:
		$a0 at pe.entry_point
}
