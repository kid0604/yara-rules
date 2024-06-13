rule Windows_Generic_Threat_d7b57912
{
	meta:
		author = "Elastic Security"
		id = "d7b57912-02b4-421a-8f93-9e8371314e68"
		fingerprint = "36a3fecc918cd891d9c779f7ff54019908ba190853739c8059adb84233643a1c"
		creation_date = "2024-05-23"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "0906599be152dd598c7f540498c44cc38efe9ea976731da05137ee6520288fe4"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 83 C4 B8 53 56 8B DA 89 45 FC 8D 45 FC ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 64 FF 30 64 89 20 8B C3 ?? ?? ?? ?? ?? 6A 00 6A 00 8D 45 F0 50 8B 45 FC }

	condition:
		all of them
}
