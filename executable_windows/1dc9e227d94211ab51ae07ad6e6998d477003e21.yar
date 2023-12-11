import "pe"

rule ShrinkWrapv14
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of ShrinkWrapv14 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 58 60 8B E8 55 33 F6 68 48 01 [2] E8 49 01 [2] EB }

	condition:
		$a0 at pe.entry_point
}
