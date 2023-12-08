rule Windows_Trojan_Qbot_d91c1384
{
	meta:
		author = "Elastic Security"
		id = "d91c1384-839f-4062-8a8d-5cda931029ae"
		fingerprint = "1b47ede902b6abfd356236e91ed3e741cf1744c68b6bb566f0d346ea07fee49a"
		creation_date = "2021-07-08"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Qbot"
		reference_sample = "18ac3870aaa9aaaf6f4a5c0118daa4b43ad93d71c38bf42cb600db3d786c6dda"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Qbot with fingerprint d91c1384"
		filetype = "executable"

	strings:
		$a = { FE 8A 14 06 88 50 FF 8A 54 BC 11 88 10 8A 54 BC 10 88 50 01 47 83 }

	condition:
		all of them
}
