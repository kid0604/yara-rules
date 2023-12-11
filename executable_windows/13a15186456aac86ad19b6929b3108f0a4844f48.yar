import "pe"

rule FSGv133Engdulekxt
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of FSGv133Engdulekxt malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF }
		$a1 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
