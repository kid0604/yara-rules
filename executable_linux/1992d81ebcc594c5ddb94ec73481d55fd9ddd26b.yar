rule Linux_Trojan_Malxmr_144994a5
{
	meta:
		author = "Elastic Security"
		id = "144994a5-1e37-4913-b7aa-deed638b1a79"
		fingerprint = "473e686a74e76bb879b3e34eb207d966171f3e11cf68bde364316c2ae5cd3dc3"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Malxmr"
		reference_sample = "07db41a4ddaac802b04df5e5bbae0881fead30cb8f6fa53a8a2e1edf14f2d36b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Malxmr"
		filetype = "executable"

	strings:
		$a = { 78 71 51 58 5A 5A 4D 31 5A 35 59 6B 4D 78 61 47 4A 58 55 54 4A }

	condition:
		all of them
}
