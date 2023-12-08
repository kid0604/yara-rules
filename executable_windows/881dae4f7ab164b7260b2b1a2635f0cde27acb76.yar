import "pe"

rule FSGv110EngdulekxtMASM32TASM32_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects FSGv110EngdulekxtMASM32TASM32_alt_1 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B }
		$a1 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B F2 81 F6 EE 00 00 00 EB 02 CD 20 8A 0B E8 02 00 00 00 A9 54 5E C1 EE 07 F7 D7 EB 01 DE 81 E9 B7 96 A0 C4 EB 01 6B EB 02 CD 20 80 E9 4B C1 CF 08 EB 01 71 80 E9 1C EB }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
