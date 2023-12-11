import "pe"

rule FSGv110EngdulekxtMicrosoftVisualC60ASM
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of FSGv110EngdulekxtMicrosoftVisualC60ASM malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { F7 D0 EB 02 CD 20 BE BB 74 1C FB EB 02 CD 20 BF 3B [2] FB C1 C1 03 33 F7 EB 02 CD 20 68 }

	condition:
		$a0 at pe.entry_point
}
