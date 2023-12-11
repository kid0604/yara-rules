rule Linux_Exploit_Enoket_5969a348
{
	meta:
		author = "Elastic Security"
		id = "5969a348-6573-4cb3-b81e-db455ff7b484"
		fingerprint = "7e9b9ba6146754857632451be2f98a5008268091ae1cfab1a87322b6fe30097c"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Enoket"
		reference_sample = "4b4d7ca9e1ffa2c46cb097d4a014c59b1a9feb93b3adcb5936ef6a1dfef9b0ae"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Linux exploit Enoket"
		filetype = "executable"

	strings:
		$a = { FC 83 7D FC FF 75 07 B8 FF FF FF FF EB 0F 8B 45 FC 01 45 F0 83 7D }

	condition:
		all of them
}
