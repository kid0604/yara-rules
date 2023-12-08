import "pe"

rule FSGv110EngdulekxtMicrosoftVisualC6070ASM
{
	meta:
		author = "malware-lu"
		description = "Detects the FSGv110EngdulekxtMicrosoftVisualC6070ASM malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 01 00 00 00 5A 5E E8 02 00 00 00 BA DD 5E 03 F2 EB 01 64 BB 80 [2] 00 8B FA EB 01 A8 }

	condition:
		$a0 at pe.entry_point
}
