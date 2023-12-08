rule Linux_Trojan_Kaiji_dcf6565e
{
	meta:
		author = "Elastic Security"
		id = "dcf6565e-8287-4d78-b103-53cfab192025"
		fingerprint = "381d6b8f6a95800fe0d20039f991ce82317f60aef100487f3786e6c1e63376e1"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Kaiji"
		reference_sample = "49f3086105bdc160248e66334db00ce37cdc9167a98faac98800b2c97515b6e7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Kaiji"
		filetype = "executable"

	strings:
		$a = { 48 69 D2 9B 00 00 00 48 C1 EA 20 83 C2 64 48 8B 9C 24 B8 00 }

	condition:
		all of them
}
