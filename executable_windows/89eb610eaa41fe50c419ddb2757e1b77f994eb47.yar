import "pe"

rule EmbedPE113cyclotron
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the EmbedPE113cyclotron malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68 B8 5E 2D C6 DA FD 48 63 05 3C 71 B8 5E 97 7C 36 7E 32 7C 08 4F 06 51 64 10 A3 F1 4E CF 25 CB 80 D2 99 54 46 ED E1 D3 46 86 2D 10 68 93 83 5C 46 4D 43 9B 8C D6 7C BB 99 69 97 71 2A 2F A3 38 6B 33 }

	condition:
		$a0 at pe.entry_point
}
