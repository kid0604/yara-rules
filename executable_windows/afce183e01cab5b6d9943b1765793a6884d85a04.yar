import "pe"

rule ExeToolsCOM2EXE
{
	meta:
		author = "malware-lu"
		description = "Detects the ExeToolsCOM2EXE malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] 5D 83 ED ?? 8C DA 2E 89 96 [2] 83 C2 ?? 8E DA 8E C2 2E 01 96 [2] 60 }

	condition:
		$a0 at pe.entry_point
}
