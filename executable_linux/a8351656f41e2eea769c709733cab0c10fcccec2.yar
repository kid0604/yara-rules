rule Linux_Trojan_Tsunami_019f0e75
{
	meta:
		author = "Elastic Security"
		id = "019f0e75-a766-4778-8337-c5bce478ecd9"
		fingerprint = "3b66dcdd89ce564cf81689ace33ee91682972421a9926efa1985118cefebdddc"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "575b0dc887d132aa3983e5712b8f642b03762b0685fbd5a32c104bca72871857"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Tsunami"
		filetype = "executable"

	strings:
		$a = { 2E 0A 00 2B 73 74 64 00 2B 73 74 6F 70 00 2B 75 6E 6B 6E 6F }

	condition:
		all of them
}
