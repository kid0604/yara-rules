import "pe"

rule FSGv131Engdulekxt
{
	meta:
		author = "malware-lu"
		description = "Detects the FSGv131Engdulekxt malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE [3] 00 53 BB [3] 00 B2 80 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 48 13 C9 EB }

	condition:
		$a0 at pe.entry_point
}
