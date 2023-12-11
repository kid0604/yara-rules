import "pe"

rule MAL_Emotet_Jan20_1
{
	meta:
		description = "Detects Emotet malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://app.any.run/tasks/5e81638e-df2e-4a5b-9e45-b07c38d53929/"
		date = "2020-01-29"
		hash1 = "e7c22ccdb1103ee6bd15c528270f56913bb2f47345b360802b74084563f1b73d"
		os = "windows"
		filetype = "executable"

	strings:
		$op0 = { 74 60 8d 34 18 eb 54 03 c3 50 ff 15 18 08 41 00 }
		$op1 = { 03 fe 66 39 07 0f 85 2a ff ff ff 8b 4d f0 6a 20 }
		$op2 = { 8b 7d fc 0f 85 49 ff ff ff 85 db 0f 84 d1 }

	condition:
		uint16(0)==0x5a4d and filesize <=200KB and (pe.imphash()=="009889c73bd2e55113bf6dfa5f395e0d" or 1 of them )
}
