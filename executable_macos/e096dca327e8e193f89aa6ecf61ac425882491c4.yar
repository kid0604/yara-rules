rule MacOS_Trojan_Genieo_37878473
{
	meta:
		author = "Elastic Security"
		id = "37878473-b6f8-4cbe-ba70-31ecddf41c82"
		fingerprint = "e9760bda6da453f75e543c919c260a4560989f62f3332f28296283d4c01b62a2"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Genieo"
		reference_sample = "0fadd926f8d763f7f15e64f857e77f44a492dcf5dc82ae965d3ddf80cd9c7a0d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "MacOS.Trojan.Genieo is a trojan horse that targets macOS systems and is known for its malicious activities."
		filetype = "executable"

	strings:
		$a = { 65 72 6E 61 6C 44 6F 77 6E 4C 6F 61 64 55 72 6C 46 6F 72 42 72 61 6E 64 3A 5D }

	condition:
		all of them
}
