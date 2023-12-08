rule Linux_Trojan_Getshell_3cf5480b
{
	meta:
		author = "Elastic Security"
		id = "3cf5480b-bb21-4a6e-a078-4b145d22c79f"
		fingerprint = "3ef0817445c54994d5a6792ec0e6c93f8a51689030b368eb482f5ffab4761dd2"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Getshell"
		reference = "0e41c0d6286fb7cd3288892286548eaebf67c16f1a50a69924f39127eb73ff38"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Getshell"
		filetype = "executable"

	strings:
		$a = { B2 24 B0 03 CD 80 85 C0 78 02 FF E1 B8 01 00 00 00 BB 01 00 }

	condition:
		all of them
}
