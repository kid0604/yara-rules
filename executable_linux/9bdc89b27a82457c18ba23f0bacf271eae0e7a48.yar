rule Linux_Trojan_Tsunami_0c6686b8
{
	meta:
		author = "Elastic Security"
		id = "0c6686b8-8880-4a2c-ba70-9a9840a618b0"
		fingerprint = "7bab1c0cf4fb79c50369f991373178ef3b5d3f7afd765dac06e86ac0c27e0c83"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "409c55110d392aed1a9ec98a6598fb8da86ab415534c8754aa48e3949e7c4b62"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Tsunami with ID 0c6686b8"
		filetype = "executable"

	strings:
		$a = { 45 F8 31 C0 48 8B 45 C8 0F B7 40 02 66 89 45 D0 48 8B 45 C8 8B }

	condition:
		all of them
}
