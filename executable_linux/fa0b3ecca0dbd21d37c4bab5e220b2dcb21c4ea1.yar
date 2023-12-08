rule Linux_Trojan_Gafgyt_7167d08f
{
	meta:
		author = "Elastic Security"
		id = "7167d08f-bfeb-4d78-9783-3a1df2ef0ed3"
		fingerprint = "b9df4ab322a2a329168f684b07b7b05ee3d03165c5b9050a4710eae7aeca6cd9"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with ID 7167d08f"
		filetype = "executable"

	strings:
		$a = { 0C 8A 00 3C 2D 75 13 FF 45 0C C7 45 E4 01 00 00 00 EB 07 FF }

	condition:
		all of them
}
