import "pe"

rule EXEPACKLINKv360v364v365or50121
{
	meta:
		author = "malware-lu"
		description = "Detects executable files packed with specific packers"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8C C0 05 [2] 0E 1F A3 [2] 03 [3] 8E C0 8B [3] 8B ?? 4F 8B F7 FD F3 A4 50 B8 [2] 50 CB }

	condition:
		$a0 at pe.entry_point
}
