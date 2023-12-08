import "pe"

rule FSGv110EngdulekxtMicrosoftVisualBasic5060
{
	meta:
		author = "malware-lu"
		description = "Detects the FSGv110EngdulekxtMicrosoftVisualBasic5060 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { C1 CB 10 EB 01 0F B9 03 74 F6 EE 0F B6 D3 8D 05 83 [2] EF 80 F3 F6 2B C1 EB 01 DE 68 77 }

	condition:
		$a0 at pe.entry_point
}
