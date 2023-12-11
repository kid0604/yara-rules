import "pe"

rule ShellModify01pll621
{
	meta:
		author = "malware-lu"
		description = "Detects shell modification in PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 98 66 41 00 68 3C 3D 41 00 64 A1 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
