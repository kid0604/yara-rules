rule Windows_Trojan_Vidar_9007feb2
{
	meta:
		author = "Elastic Security"
		id = "9007feb2-6ad1-47b6-bae2-3379d114e4f1"
		fingerprint = "8416b14346f833264e32c63253ea0b0fe28e5244302b2e1b266749c543980fe2"
		creation_date = "2021-06-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Vidar"
		reference_sample = "34c0cb6eaf2171d3ab9934fe3f962e4e5f5e8528c325abfe464d3c02e5f939ec"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Vidar"
		filetype = "executable"

	strings:
		$a = { E8 53 FF D6 50 FF D7 8B 45 F0 8D 48 01 8A 10 40 3A D3 75 F9 }

	condition:
		all of them
}
