rule Windows_Generic_MalCert_d3a0db6b
{
	meta:
		author = "Elastic Security"
		id = "d3a0db6b-61ce-4000-a3f5-bf6b7c7dd5dc"
		fingerprint = "3f89a2e00e85cd5f01564632c152ecdd22971b7a1a1381959571d475d592155d"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "d0ce783b1582863fa56696b8bc7c393723f9ff53552fadc221e516f39b3c165e"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 08 32 EF 74 6F 16 E6 73 1B }

	condition:
		all of them
}
