rule Linux_Cryptominer_Camelot_29c1c386
{
	meta:
		author = "Elastic Security"
		id = "29c1c386-c09c-4a58-b454-fc8feb78051d"
		fingerprint = "2ad8d0d00002c969c50fde6482d797d76d60572db5935990649054b5a103c5d1"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Camelot"
		reference_sample = "fc73bbfb12c64d2f20efa22a6d8d8c5782ef57cb0ca6d844669b262e80db2444"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Camelot"
		filetype = "executable"

	strings:
		$a = { 65 20 62 72 61 6E 63 68 00 00 00 49 67 6E 6F 72 69 6E 67 20 }

	condition:
		all of them
}
