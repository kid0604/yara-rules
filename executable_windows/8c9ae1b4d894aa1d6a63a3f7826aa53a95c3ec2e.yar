rule Windows_Trojan_Generic_889b1248
{
	meta:
		author = "Elastic Security"
		id = "889b1248-a694-4c9b-8792-c04e582e814c"
		fingerprint = "a5e0c2bbd6a297c01f31eccabcbe356730f50f074587f679da6caeca99e54bc1"
		creation_date = "2022-03-11"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.Generic"
		reference_sample = "a48d57a139c7e3efa0c47f8699e2cf6159dc8cdd823b16ce36257eb8c9d14d53"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Generic"
		filetype = "executable"

	strings:
		$a1 = "BELARUS-VIRUS-MAKER" ascii fullword
		$a2 = "C:\\windows\\temp\\" ascii fullword
		$a3 = "~c~a~n~n~a~b~i~s~~i~s~~n~o~t~~a~~d~r~u~g~" ascii fullword
		$a4 = "untInfector" ascii fullword

	condition:
		all of them
}
