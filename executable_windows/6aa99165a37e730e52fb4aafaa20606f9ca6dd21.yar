import "pe"

rule PACKWINv101p
{
	meta:
		author = "malware-lu"
		description = "Detects the PACKWINv101p malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8C C0 FA 8E D0 BC [2] FB 06 0E 1F 2E [4] 8B F1 4E 8B FE 8C DB 2E [4] 8E C3 FD F3 A4 53 B8 [2] 50 CB }

	condition:
		$a0 at pe.entry_point
}
