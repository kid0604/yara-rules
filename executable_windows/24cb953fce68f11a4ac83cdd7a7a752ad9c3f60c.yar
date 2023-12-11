import "pe"

rule FSGv120EngdulekxtBorlandDelphiBorlandC
{
	meta:
		author = "malware-lu"
		description = "Detects Borland Delphi or Borland C compiled files with FSG v1.20 encryption"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 [2] 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 E9 F9 BB F4 00 00 00 EB 02 8F D0 EB 02 08 AD 8A 16 2B C7 1B C7 80 C2 7A 41 80 EA 10 EB 01 3C 81 EA CF AE F1 AA EB 01 EC 81 EA BB C6 AB EE 2C E3 32 D3 0B CB 81 EA AB }

	condition:
		$a0 at pe.entry_point
}
