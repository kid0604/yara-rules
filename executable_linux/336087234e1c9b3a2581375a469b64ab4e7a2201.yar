rule Linux_Cryptominer_Xmrminer_02d19c01
{
	meta:
		author = "Elastic Security"
		id = "02d19c01-51e9-4a46-a06b-d5f7e97285d9"
		fingerprint = "724bbc2910217bcac457e6ba0c0848caf38e12f272b0104ade1c7bc57dc85c27"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrminer"
		reference_sample = "b6df662f5f7566851b95884c0058e7476e49aeb7a96d2aa203393d88e584972f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrminer malware"
		filetype = "executable"

	strings:
		$a = { 4C 8D 7E 15 41 56 41 55 41 54 41 BB 03 00 00 00 55 53 48 89 FB 48 }

	condition:
		all of them
}
