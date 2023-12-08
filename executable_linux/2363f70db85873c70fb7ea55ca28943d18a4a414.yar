rule Linux_Exploit_CVE_2019_13272_583dd2c0
{
	meta:
		author = "Elastic Security"
		id = "583dd2c0-9e94-4d38-bdff-e6c3b7c7d594"
		fingerprint = "afc96d47ad2564f69d2fb9a39e882bfc5b4879f0a8abbf36d5e3af6a52dccd63"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2019-13272"
		reference_sample = "3191b9473f3e59f55e062e6bdcfe61b88974602c36477bfa6855ccd92ff7ca83"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Linux kernel exploit for CVE-2019-13272"
		filetype = "executable"

	strings:
		$a = { 48 89 85 40 FF FF FF 48 8B 45 D8 48 83 C0 20 48 89 85 38 FF }

	condition:
		all of them
}
