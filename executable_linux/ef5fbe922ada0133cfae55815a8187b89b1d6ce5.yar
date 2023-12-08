rule Linux_Trojan_Mirai_ab804bb7
{
	meta:
		author = "Elastic Security"
		id = "ab804bb7-57ab-48db-85cc-a6d88de0c84a"
		fingerprint = "b9716aa7be1b0e4c966a25a40521114e33c21c7ec3c4468afc1bf8378dd11932"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "8f0cc764729498b4cb9c5446f1a84cde54e828e913dc78faf537004a7df21b20"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with fingerprint ab804bb7"
		filetype = "executable"

	strings:
		$a = { 4A 75 05 0F BE 11 01 D0 89 C2 0F B7 C0 C1 FA 10 01 C2 89 D0 C1 }

	condition:
		all of them
}
