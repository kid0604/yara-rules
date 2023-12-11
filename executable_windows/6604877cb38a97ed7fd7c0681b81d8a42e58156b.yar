import "pe"

rule FSGv120EngdulekxtMASM32TASM32
{
	meta:
		author = "malware-lu"
		description = "Detects FSGv120EngdulekxtMASM32TASM32 malware based on entry point code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9 16 03 F7 EB 02 40 B0 68 F4 00 00 00 80 F1 2C 5B C1 E9 05 0F B6 C9 8A 16 0F B6 C9 0F BF C7 2A D3 E8 02 00 00 00 99 4C 58 80 EA 53 C1 C9 16 2A D3 E8 02 00 00 00 9D CE }

	condition:
		$a0 at pe.entry_point
}
