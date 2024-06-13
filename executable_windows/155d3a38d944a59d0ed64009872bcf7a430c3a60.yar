rule Windows_Exploit_Generic_8c54846d
{
	meta:
		author = "Elastic Security"
		id = "8c54846d-07ee-43bc-93e1-72bf4162ab87"
		fingerprint = "9acb35c06a21e35639c8026a18e919329db82a0629a8e2267f1f4fe00b3bb871"
		creation_date = "2024-02-29"
		last_modified = "2024-06-12"
		threat_name = "Windows.Exploit.Generic"
		reference_sample = "b6ea4815a38e606d4a2d6e6d711e610afec084db6899b7d6fc874491dd939495"
		severity = 100
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic exploit"
		filetype = "executable"

	strings:
		$a1 = { 5C 63 76 65 2D 32 30 ?? ?? 2D ?? ?? ?? ?? 5C 78 36 34 5C 52 65 6C 65 61 73 65 5C }
		$a2 = { 5C 43 56 45 2D 32 30 ?? ?? 2D ?? ?? ?? ?? 5C 78 36 34 5C 52 65 6C 65 61 73 65 5C }
		$a3 = { 5C 78 36 34 5C 52 65 6C 65 61 73 65 5C 43 56 45 2D 32 30 ?? ?? 2D ?? ?? ?? ?? ?? 2E 70 64 62 }
		$a4 = { 5C 52 65 6C 65 61 73 65 5C 43 56 45 2D 32 30 ?? ?? 2D }
		$a5 = "\\x64\\Release\\CmdTest.pdb"
		$a6 = "\\x64\\Release\\RunPS.pdb"
		$a7 = "X:\\tools\\0day\\"
		$a8 = "C:\\work\\volodimir_"
		$a9 = { 78 36 34 5C 52 65 6C 65 61 73 65 5C 65 78 70 6C 6F 69 74 2E 70 64 62 }
		$b1 = { 5C 43 56 45 2D 32 30 ?? ?? 2D }
		$b2 = { 5C 78 36 34 5C 52 65 6C 65 61 73 65 5C }

	condition:
		any of ($a*) or all of ($b*)
}
