rule Windows_Ransomware_Hive_b97ec33b
{
	meta:
		author = "Elastic Security"
		id = "b97ec33b-d4cf-4b70-8ce8-8a5d20448643"
		fingerprint = "7f2c2d299942390d953599b180ed191d9db999275545a7ba29059fd49b858087"
		creation_date = "2021-08-26"
		last_modified = "2022-01-13"
		threat_name = "Windows.Ransomware.Hive"
		reference_sample = "50ad0e6e9dc72d10579c20bb436f09eeaa7bfdbcb5747a2590af667823e85609"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Ransomware Hive"
		filetype = "executable"

	strings:
		$a1 = { 74 C3 8B 44 24 78 8B 08 8B 50 04 8B 40 08 89 0C 24 89 54 24 04 89 44 }

	condition:
		all of them
}
