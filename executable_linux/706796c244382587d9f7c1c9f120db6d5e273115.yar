rule Linux_Cryptominer_Generic_37c3f8d3
{
	meta:
		author = "Elastic Security"
		id = "37c3f8d3-9d79-434c-b0e8-252122ebc62a"
		fingerprint = "6ba0bae987db369ec6cdadf685b8c7184e6c916111743f1f2b43ead8d028338c"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "efbddf1020d0845b7a524da357893730981b9ee65a90e54976d7289d46d0ffd4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { F0 4C 01 F0 49 8B 75 08 48 01 C3 49 39 F4 74 29 48 89 DA 4C }

	condition:
		all of them
}
