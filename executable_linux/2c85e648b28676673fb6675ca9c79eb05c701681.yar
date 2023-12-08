rule Linux_Cryptominer_Generic_467c4d46
{
	meta:
		author = "Elastic Security"
		id = "467c4d46-3272-452c-9251-3599d16fc916"
		fingerprint = "cbde94513576fdb7cabf568bd8439f0194d6800373c3735844e26d262c8bc1cc"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "388b927b850b388e0a46a6c9a22b733d469e0f93dc053ebd78996e903b25e38a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 49 8B 77 08 48 21 DE 4C 39 EE 75 CE 66 41 83 7F 1E 04 4C 89 F5 }

	condition:
		all of them
}
