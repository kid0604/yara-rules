rule Windows_Trojan_Metasploit_96233b6b
{
	meta:
		author = "Elastic Security"
		id = "96233b6b-d95a-4e0e-8f83-f2282a342087"
		fingerprint = "40032849674714bc9eb020971dd9f27a07b53b8ff953b793cb3aad136256fd70"
		creation_date = "2021-06-10"
		last_modified = "2021-08-23"
		description = "Identifies another 64 bit API hashing function used by Metasploit."
		threat_name = "Windows.Trojan.Metasploit"
		reference_sample = "e7a2d966deea3a2df6ce1aeafa8c2caa753824215a8368e0a96b394fb46b753b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 31 FF 0F B7 4A 26 31 C0 AC 3C 61 7C 02 2C 20 C1 CF 0D }

	condition:
		all of them
}
