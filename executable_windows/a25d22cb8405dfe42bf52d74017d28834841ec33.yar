import "pe"

rule EXEManagerVersion301994cSolarDesigner
{
	meta:
		author = "malware-lu"
		description = "Detects EXE file with specific version and author"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B4 30 1E 06 CD 21 2E [3] BF [2] B9 [2] 33 C0 2E [2] 47 E2 }

	condition:
		$a0 at pe.entry_point
}
