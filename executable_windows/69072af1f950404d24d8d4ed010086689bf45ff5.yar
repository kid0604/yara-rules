import "pe"

rule JExeCompressor10byArashVeyskarami
{
	meta:
		author = "malware-lu"
		description = "Detects JExeCompressor 1.0 by Arash Veyskarami"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8D 2D D3 4A E5 14 0F BB F7 0F BA E5 73 0F AF D5 8D 0D 0C 9F E6 11 C0 F8 EF F6 DE 80 DC 5B F6 DA 0F A5 C1 0F C1 F1 1C F3 4A 81 E1 8C 1F 66 91 0F BE C6 11 EE 0F C0 E7 33 D9 64 F2 C0 DC 73 0F C0 D5 55 8B EC BA C0 1F 41 00 8B C2 B9 97 00 00 00 80 32 79 50 B8 02 00 00 00 50 03 14 24 58 58 51 2B C9 B9 01 00 00 00 83 EA 01 E2 FB 59 E2 E1 FF E0 }

	condition:
		$a0 at pe.entry_point
}
