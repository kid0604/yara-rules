rule Linux_Trojan_Mirai_0bce98a2
{
	meta:
		author = "Elastic Security"
		id = "0bce98a2-113e-41e1-95c9-9e1852b26142"
		fingerprint = "993d0d2e24152d0fb72cc5d5add395bed26671c3935f73386341398b91cb0e6e"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "1b20df8df7f84ad29d81ccbe276f49a6488c2214077b13da858656c027531c80"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with ID 0bce98a2"
		filetype = "executable"

	strings:
		$a = { 4B 52 41 00 46 47 44 43 57 4E 56 00 48 57 43 4C 56 47 41 4A }

	condition:
		all of them
}
