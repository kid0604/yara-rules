import "pe"

rule DzAPatcherv13Loader
{
	meta:
		author = "malware-lu"
		description = "Detects DzAPatcherv13 loader"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BF 00 40 40 00 99 68 48 20 40 00 68 00 20 40 00 52 52 52 52 52 52 52 57 E8 15 01 00 00 85 C0 75 1C 99 52 52 57 52 E8 CB 00 00 00 FF 35 4C 20 40 00 E8 D2 00 00 00 6A 00 E8 BF 00 00 00 99 68 58 20 40 00 52 52 68 63 10 40 00 52 52 E8 DB 00 00 00 6A FF FF 35 }

	condition:
		$a0
}
