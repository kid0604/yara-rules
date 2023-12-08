rule Linux_Cryptominer_Generic_1b76c066
{
	meta:
		author = "Elastic Security"
		id = "1b76c066-463c-46e5-8a08-ccfc80e3f399"
		fingerprint = "e33937322a1a2325539d7cdb1df13295e5ca041a513afe1d5e0941f0c66347dd"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "f60302de1a0e756e3af9da2547a28da5f57864191f448e341af1911d64e5bc8b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 0C 14 89 0C 10 48 83 C2 04 48 83 FA 20 75 EF 48 8D 8C 24 F0 00 }

	condition:
		all of them
}
