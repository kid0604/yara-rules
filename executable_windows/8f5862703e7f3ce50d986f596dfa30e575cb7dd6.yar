import "pe"

rule NFOv10
{
	meta:
		author = "malware-lu"
		description = "Detects NFOv10 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8D 50 12 2B C9 B1 1E 8A 02 34 77 88 02 42 E2 F7 C8 8C }

	condition:
		$a0 at pe.entry_point
}
