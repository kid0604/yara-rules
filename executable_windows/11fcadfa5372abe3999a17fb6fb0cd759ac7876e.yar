rule Windows_Trojan_Matanbuchus_b521801b
{
	meta:
		author = "Elastic Security"
		id = "b521801b-5623-4bfe-9a9d-9e16afa63c63"
		fingerprint = "7792cffc82678bb05ba1aa315011317611eb0bf962665e0657a7db2ce95f81b4"
		creation_date = "2022-03-17"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.Matanbuchus"
		reference_sample = "4eb85a5532b98cbc4a6db1697cf46b9e2b7e28e89d6bbfc137b36c0736cd80e2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Matanbuchus"
		filetype = "executable"

	strings:
		$a1 = "%PROCESSOR_ARCHITECTURE%" ascii fullword
		$a2 = "%PROCESSOR_REVISION%\\" ascii fullword
		$a3 = "%LOCALAPPDATA%\\" ascii fullword
		$a4 = "\"C:\\Windows\\system32\\schtasks.exe\" /Create /SC MINUTE /MO 1 /TN" ascii fullword

	condition:
		all of them
}
