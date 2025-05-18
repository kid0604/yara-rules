rule Windows_Generic_MalCert_397a556e
{
	meta:
		author = "Elastic Security"
		id = "397a556e-e296-462f-a6d6-1c2c14cee518"
		fingerprint = "c1f11e65e86c6e4d8e84ea9d3ac2f84102449c8c67cc445d4348e6a9885de203"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "f13869390dda83d40960d4f8a6b438c5c4cd31b4d25def7726c2809ddc573dc7"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 0C 1C E3 9E A1 C9 FC 35 F6 CC 05 A8 40 }

	condition:
		all of them
}
