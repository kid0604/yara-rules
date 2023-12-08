import "pe"

rule MarjinZEXEScramblerSEbyMarjinZ
{
	meta:
		author = "malware-lu"
		description = "Detects MarjinZ EXE Scrambler SE by MarjinZ"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 A3 02 00 00 E9 35 FD FF FF FF 25 C8 20 00 10 6A 14 68 C0 21 00 10 E8 E4 01 00 00 FF 35 7C 33 00 10 8B 35 8C 20 00 10 FF D6 59 89 45 E4 83 F8 FF 75 0C FF 75 08 FF 15 88 20 00 10 59 EB 61 6A 08 E8 02 03 00 00 59 83 65 FC 00 FF 35 7C 33 00 10 FF D6 89 45 E4 FF 35 78 33 00 10 FF D6 89 45 E0 8D 45 E0 50 8D 45 E4 50 FF 75 08 E8 D1 02 00 00 89 45 DC FF 75 E4 8B 35 74 20 00 10 FF D6 A3 7C 33 00 10 FF 75 E0 FF D6 83 C4 1C A3 78 33 00 10 C7 45 FC FE FF FF FF E8 09 00 00 00 8B 45 DC E8 A0 01 00 00 C3 }

	condition:
		$a0
}
