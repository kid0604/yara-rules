import "pe"

rule APT_FIN7_MsDoc_Sep21_1
{
	meta:
		description = "Detects MalDocs used by FIN7 group"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.anomali.com/blog/cybercrime-group-fin7-using-windows-11-alpha-themed-docs-to-drop-javascript-backdoor"
		date = "2021-09-07"
		score = 85
		hash1 = "d60b6a8310373c9b84e6760c24185535"
		os = "windows"
		filetype = "document"

	strings:
		$xc1 = { 00 4A 00 6F 00 68 00 6E 00 0B 00 57 00 31 00 30
               00 50 00 72 00 6F 00 4F 00 66 00 66 00 31 00 36 }
		$s1 = "word_data.bin" ascii fullword
		$s2 = "V:\\DOC\\For_JS" ascii
		$s3 = "HomeCompany" ascii
		$s4 = "W10ProOff16" ascii

	condition:
		uint16(0)==0xcfd0 and (1 of ($x*) or 3 of them )
}
