rule Linux_Cryptominer_Malxmr_21d0550b
{
	meta:
		author = "Elastic Security"
		id = "21d0550b-4f15-4481-ba9c-2be26ea8f81a"
		fingerprint = "5b556d2e3e48fda57c741c4c7b9efb72aad579e5055df366cdb9cfa38e496494"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Malxmr"
		reference_sample = "07db41a4ddaac802b04df5e5bbae0881fead30cb8f6fa53a8a2e1edf14f2d36b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Malxmr malware"
		filetype = "executable"

	strings:
		$a = { 3B 31 C0 48 83 C9 FF 48 89 EE F2 AE 48 8B 3B 48 F7 D1 48 FF C9 }

	condition:
		all of them
}
