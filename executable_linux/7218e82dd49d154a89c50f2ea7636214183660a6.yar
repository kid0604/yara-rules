rule Linux_Trojan_Tsunami_97288af8
{
	meta:
		author = "Elastic Security"
		id = "97288af8-f447-48ba-9df3-4e90f1420249"
		fingerprint = "a1e20b699822b47359c8585ff01da06f585b9d7187a433fe0151394b16aa8113"
		creation_date = "2021-12-13"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "c39eb055c5f71ebfd6881ff04e876f49495c0be5560687586fc47bf5faee0c84"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Tsunami"
		filetype = "executable"

	strings:
		$a = { 61 6E 64 65 6D 6F 20 73 68 69 72 61 6E 61 69 20 77 61 20 79 6F 2C }

	condition:
		all of them
}
