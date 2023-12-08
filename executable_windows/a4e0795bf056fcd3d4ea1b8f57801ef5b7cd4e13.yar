rule Windows_Trojan_Netwire_6a7df287
{
	meta:
		author = "Elastic Security"
		id = "6a7df287-1656-4779-9a96-c0ab536ae86a"
		fingerprint = "85051a0b94da4388eaead4c4f4b2d16d4a5eb50c3c938b3daf5c299c9c12f1e6"
		creation_date = "2021-06-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Netwire"
		reference_sample = "e6f446dbefd4469b6c4d24988dd6c9ccd331c8b36bdbc4aaf2e5fc49de2c3254"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Netwire variant 6a7df287"
		filetype = "executable"

	strings:
		$a = { 0F B6 74 0C 10 89 CF 29 C7 F7 C6 DF 00 00 00 74 09 41 89 F3 88 5C }

	condition:
		all of them
}
