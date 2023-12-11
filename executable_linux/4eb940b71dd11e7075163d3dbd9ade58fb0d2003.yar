rule Linux_Trojan_Tsunami_87bcb848
{
	meta:
		author = "Elastic Security"
		id = "87bcb848-cd8b-478c-87de-5df8c457024c"
		fingerprint = "ffd1a95ba4801bb51ce9b688bdb9787d4a8e3bc3a60ad0f52073f5c531bc6df7"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "575b0dc887d132aa3983e5712b8f642b03762b0685fbd5a32c104bca72871857"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Tsunami"
		filetype = "executable"

	strings:
		$a = { 65 6D 6F 74 65 00 52 65 6D 6F 74 65 20 49 52 43 20 42 6F 74 00 23 }

	condition:
		all of them
}
