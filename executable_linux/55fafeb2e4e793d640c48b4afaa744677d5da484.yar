rule Linux_Cryptominer_Camelot_73e2373e
{
	meta:
		author = "Elastic Security"
		id = "73e2373e-75ac-4385-b663-a50423626fc8"
		fingerprint = "6ce73e55565e9119a355b91ec16c2147cc698b1a57cc29be22639b34ba39eea9"
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
		$a = { 45 F8 48 83 7D F8 00 74 4D 48 8B 55 80 48 8D 45 A0 48 89 D6 48 }

	condition:
		all of them
}
