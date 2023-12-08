rule MacOS_Trojan_Amcleaner_a91d3907
{
	meta:
		author = "Elastic Security"
		id = "a91d3907-5e24-46c0-90ef-ed7f46ad8792"
		fingerprint = "c020567fde77a72d27c9c06f6ebb103f910321cc7a1c3b227e0965b079085b49"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Amcleaner"
		reference_sample = "dc9c700f3f6a03ecb6e3f2801d4269599c32abce7bc5e6a1b7e6a64b0e025f58"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS.Trojan.Amcleaner"
		filetype = "executable"

	strings:
		$a = { 40 22 4E 53 49 6D 61 67 65 56 69 65 77 22 2C 56 69 6E 6E 76 63 6A 76 64 69 5A }

	condition:
		all of them
}
