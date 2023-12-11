rule MacOS_Virus_Maxofferdeal_20a0091e
{
	meta:
		author = "Elastic Security"
		id = "20a0091e-a3ef-4a13-ba92-700f3583e06d"
		fingerprint = "1629b34b424816040066122592e56e317b204f3d5de2f5e7f68114c7a48d99cb"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Virus.Maxofferdeal"
		reference_sample = "b00a61c908cd06dbc26bee059ba290e7ce2ad6b66c453ea272c7287ffa29c5ab"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS.Virus.Maxofferdeal"
		filetype = "executable"

	strings:
		$a = { F2 E7 E7 BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 A0 BC BC B8 F2 E7 E7 BF }

	condition:
		all of them
}
