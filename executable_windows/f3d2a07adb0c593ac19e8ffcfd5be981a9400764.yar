import "pe"

rule APT_Winnti_MAL_Dec19_4
{
	meta:
		description = "Detects Winnti malware"
		author = "Unknown"
		reference = "https://www.verfassungsschutz.de/download/broschuere-2019-12-bfv-cyber-brief-2019-01.pdf"
		date = "2019-12-06"
		score = 75
		os = "windows"
		filetype = "executable"

	strings:
		$b1 = { 4C 8D 41 24 33 D2 B9 03 00 1F 00 FF 9? F8 00 00 00 48 85 C0 74 }
		$b2 = { 4C 8B 4? 08 BA 01 00 00 00 49 8B C? FF D0 85 C0 [2-6] C7 4? 1C 01 00 00 00 B8 01 00 00 00 }
		$b3 = { 8B 4B E4 8B 53 EC 41 B8 00 40 00 00 4? 0B C? FF 9? B8 00 00 00 EB }

	condition:
		(2 of ($b*))
}
