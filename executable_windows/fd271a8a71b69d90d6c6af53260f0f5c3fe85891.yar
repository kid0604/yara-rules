import "pe"

rule ANDpakk2006DmitryAndreev
{
	meta:
		author = "malware-lu"
		description = "Detects ANDpakk2006DmitryAndreev malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 FC BE D4 00 40 00 BF 00 10 00 01 57 83 CD FF 33 C9 F9 EB 05 A4 02 DB 75 05 8A 1E 46 12 DB 72 F4 33 C0 40 02 DB 75 05 8A 1E 46 12 DB 13 C0 02 DB 75 05 8A 1E 46 12 DB 72 0E 48 02 DB 75 05 8A 1E 46 12 DB 13 C0 EB DC 83 E8 03 72 0F C1 E0 08 AC 83 F0 FF 74 4D D1 F8 8B E8 EB 09 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 13 C9 75 1A 41 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 73 EA 83 C1 02 81 FD 00 FB FF FF 83 D1 01 56 8D 34 2F F3 A4 5E E9 73 FF FF FF C3 }

	condition:
		$a0
}
