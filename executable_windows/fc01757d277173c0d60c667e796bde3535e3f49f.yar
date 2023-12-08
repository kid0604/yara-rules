import "pe"

rule FSGv110EngdulekxtMASM32TASM32MicrosoftVisualBasic
{
	meta:
		author = "malware-lu"
		description = "Detects the FSGv110EngdulekxtMASM32TASM32MicrosoftVisualBasic malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { F7 D8 0F BE C2 BE 80 [2] 00 0F BE C9 BF 08 3B 65 07 EB 02 D8 29 BB EC C5 9A F8 EB 01 94 }

	condition:
		$a0 at pe.entry_point
}
