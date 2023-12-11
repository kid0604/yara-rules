rule Linux_Cryptominer_Generic_1d0700b8
{
	meta:
		author = "Elastic Security"
		id = "1d0700b8-1bc0-4da2-a903-9d78e79e71d8"
		fingerprint = "19853be803f82e6758554a57981e1b52c43a017ab88242c42a7c39f6ead01cf3"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "de59bee1793b88e7b48b6278a52e579770f5204e92042142cc3a9b2d683798dd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 30 42 30 42 00 22 22 03 5C DA 10 00 C0 00 60 43 9C 64 48 00 00 00 }

	condition:
		all of them
}
