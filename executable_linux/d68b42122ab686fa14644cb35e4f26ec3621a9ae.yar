rule Linux_Cryptominer_Generic_71024c4a
{
	meta:
		author = "Elastic Security"
		id = "71024c4a-e8da-44fc-9cf9-c71829dfe87a"
		fingerprint = "dbbb74ec687e8e9293dfa2272d55b81ef863a50b0ff87daf15aaf6cee473efe6"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "afe81c84dcb693326ee207ccd8aeed6ed62603ad3c8d361e8d75035f6ce7c80f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 46 08 48 89 45 08 48 8B 46 10 48 85 C0 48 89 45 10 74 BC F0 FF }

	condition:
		all of them
}
