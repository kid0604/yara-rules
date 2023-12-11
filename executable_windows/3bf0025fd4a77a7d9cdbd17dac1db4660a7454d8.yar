rule Windows_Trojan_Qbot_6fd34691
{
	meta:
		author = "Elastic Security"
		id = "6fd34691-10e4-4a66-85ff-1b67ed3da4dd"
		fingerprint = "187fc04abcba81a2cbbe839adf99b8ab823cbf65993c8780d25e7874ac185695"
		creation_date = "2022-03-07"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.Qbot"
		reference_sample = "0838cd11d6f504203ea98f78cac8f066eb2096a2af16d27fb9903484e7e6a689"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Qbot variant"
		filetype = "executable"

	strings:
		$a1 = { 75 C9 8B 45 1C 89 45 A4 8B 45 18 89 45 A8 8B 45 14 89 45 AC 8B }
		$a2 = "\\stager_1.obf\\Benign\\mfc\\" wide

	condition:
		any of them
}
