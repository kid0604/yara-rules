import "pe"

rule EXEPACKv405v406
{
	meta:
		author = "malware-lu"
		description = "Detects EXEPACK v4.05 and v4.06 packer used in Windows executable files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8C C0 05 [2] 0E 1F A3 [2] 03 06 [2] 8E C0 8B 0E [2] 8B F9 4F 8B F7 FD F3 A4 }

	condition:
		$a0 at pe.entry_point
}
