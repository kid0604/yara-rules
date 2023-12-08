rule Windows_Trojan_IcedID_11d24d35
{
	meta:
		author = "Elastic Security"
		id = "11d24d35-6bff-4fac-83d8-4d152aa0be57"
		fingerprint = "155e5df0f3f598cdc21e5c85bcf21c1574ae6788d5f7e0058be823c71d06c21e"
		creation_date = "2022-02-16"
		last_modified = "2022-04-06"
		threat_name = "Windows.Trojan.IcedID"
		reference_sample = "b8d794f6449669ff2d11bc635490d9efdd1f4e92fcb3be5cdb4b40e4470c0982"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan IcedID"
		filetype = "executable"

	strings:
		$a1 = "C:\\Users\\user\\source\\repos\\anubis\\bin\\RELEASE\\loader_dll_64.pdb" ascii fullword
		$a2 = "loader_dll_64.dll" ascii fullword

	condition:
		1 of ($a*)
}
