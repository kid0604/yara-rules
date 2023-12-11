rule Linux_Trojan_Mirai_1c0d246d
{
	meta:
		author = "Elastic Security"
		id = "1c0d246d-dc23-48d6-accb-1e1db1eba49b"
		fingerprint = "b6b6991e016419b1ddf22822ce76401370471f852866f0da25c7b0f4bec530ee"
		creation_date = "2021-04-13"
		last_modified = "2021-09-16"
		description = "Based off community provided sample"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "211cfe9d158c8a6840a53f2d1db2bf94ae689946fffb791eed3acceef7f0e3dd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		filetype = "executable"

	strings:
		$a = { E7 C0 00 51 78 0F 1B FF 8A 7C 18 27 83 2F 85 2E CB 14 50 2E }

	condition:
		all of them
}
