rule Linux_Trojan_Metasploit_ed4b2c85
{
	meta:
		author = "Elastic Security"
		id = "ed4b2c85-730f-4a77-97ed-5439a0493a4a"
		fingerprint = "c38513fa6b1ed23ec91ae316af9793c5c01ac94b43ba5502f9c32a0854aec96f"
		creation_date = "2024-05-07"
		last_modified = "2024-05-21"
		description = "Detects x64 msfvenom bind TCP random port payloads"
		threat_name = "Linux.Trojan.Metasploit"
		reference_sample = "0709a60149ca110f6e016a257f9ac35c6f64f50cfbd71075c4ca8bfe843c3211"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		filetype = "executable"

	strings:
		$str = { 6A 29 58 99 6A 01 5E 6A 02 5F 0F 05 97 B0 32 0F 05 96 B0 2B 0F 05 97 96 FF CE 6A 21 58 0F 05 75 ?? 52 48 BF 2F 2F 62 69 6E 2F 73 68 57 54 5F B0 3B 0F 05 }

	condition:
		all of them
}
