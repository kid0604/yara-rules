import "pe"

rule ILUCRYPTv4015exe
{
	meta:
		author = "malware-lu"
		description = "Detects ILUCRYPT v4.0.15 executable file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B EC FA C7 46 F7 [2] 42 81 FA [2] 75 F9 FF 66 F7 }

	condition:
		$a0 at pe.entry_point
}
