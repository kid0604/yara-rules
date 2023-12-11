rule Windows_Hacktool_Mimikatz_674fd079
{
	meta:
		author = "Elastic Security"
		id = "674fd079-f7fe-4d89-87e7-ac11aa21c9ed"
		fingerprint = "b8f71996180e5f03c10e39eb36b2084ecaff78d7af34bd3d0d75225d2cfad765"
		creation_date = "2021-04-14"
		last_modified = "2021-08-23"
		description = "Detection for default mimikatz memssp module"
		threat_name = "Windows.Hacktool.Mimikatz"
		reference_sample = "66b4a0681cae02c302a9b6f1d611ac2df8c519d6024abdb506b4b166b93f636a"
		severity = 99
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = { 44 30 00 38 00 }
		$a2 = { 48 78 00 3A 00 }
		$a3 = { 4C 25 00 30 00 }
		$a4 = { 50 38 00 78 00 }
		$a5 = { 54 5D 00 20 00 }
		$a6 = { 58 25 00 77 00 }
		$a7 = { 5C 5A 00 5C 00 }
		$a8 = { 60 25 00 77 00 }
		$a9 = { 64 5A 00 09 00 }
		$a10 = { 6C 5A 00 0A 00 }
		$a11 = { 68 25 00 77 00 }
		$a12 = { 68 25 00 77 00 }
		$a13 = { 6C 5A 00 0A 00 }
		$b1 = { 6D 69 6D 69 C7 84 24 8C 00 00 00 6C 73 61 2E C7 84 24 90 00 00 00 6C 6F 67 }

	condition:
		all of ($a*) or $b1
}
