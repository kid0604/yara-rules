rule Windows_Exploit_Generic_008359cf
{
	meta:
		author = "Elastic Security"
		id = "008359cf-5510-4f91-8cb1-7b4ff645bf2d"
		fingerprint = "3ef3b6bbe2141cb8ce47a5ee7c7531e72773d4dc4e478bb792c9230e4948db02"
		creation_date = "2024-02-28"
		last_modified = "2024-06-12"
		threat_name = "Windows.Exploit.Generic"
		reference_sample = "73225a3a54560965f4c4fae73f7ee234e31217bc06ff8ba1d0b36ebab5e76a87"
		severity = 100
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic exploit activity"
		filetype = "executable"

	strings:
		$a1 = { C6 85 ?? 01 00 00 74 C6 85 ?? 01 00 00 58 C6 85 ?? 01 00 00 58 }
		$a2 = { C6 45 ?? 41 C6 45 ?? 66 C6 45 ?? 64 C6 45 ?? 4F C6 45 ?? 70 C6 45 ?? 65 C6 45 ?? 6E C6 45 ?? 50 C6 45 ?? 61 C6 45 ?? 63 C6 45 ?? 6B C6 45 ?? 65 C6 45 ?? 74 C6 45 ?? 58 C6 45 ?? 58 }
		$b1 = "NtCreateFile"
		$b2 = "\\Device\\Afd\\Endpoint" wide nocase
		$b3 = "\\Device\\Afd\\Endpoint" nocase
		$b4 = "NtDeviceIoControlFile"

	condition:
		1 of ($a*) and 3 of ($b*)
}
