rule Linux_Trojan_Sshdoor_7c36d3dd
{
	meta:
		author = "Elastic Security"
		id = "7c36d3dd-734f-4485-85c5-906c5ecade77"
		fingerprint = "a644708905c97c784f394ebbd0020dd3b20b52b4f536c844ca860dabea36ceb7"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Sshdoor"
		reference_sample = "def4de838d58c70f9f0ae026cdad3bf09b711a55af97ed20804fa1e34e7b59e9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Sshdoor"
		filetype = "executable"

	strings:
		$a = { 24 20 48 89 E7 C1 EE 03 83 E6 01 FF D3 8B 54 24 20 31 C0 BE 20 00 }

	condition:
		all of them
}
