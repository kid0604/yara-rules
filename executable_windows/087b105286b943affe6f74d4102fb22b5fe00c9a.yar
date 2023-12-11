import "pe"

rule APT_Winnti_MAL_Dec19_1
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
		$e1 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411015}" ascii nocase
		$e2 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411014}" ascii nocase
		$e3 = "Global\\BFE_Notify_Event_{65a097fe-6102-446a-9f9c-55dfc3f411016}" ascii nocase
		$e4 = "\\BaseNamedObjects\\{B2B87CCA-66BC-4C24-89B2-C23C9EAC2A66}" wide
		$e5 = "BFE_Notify_Event_{7D00FA3C-FBDC-4A8D-AEEB-3F55A4890D2A}" nocase

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and ( any of ($e*))
}
