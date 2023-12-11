rule Windows_Ransomware_Lockbit_89e64044
{
	meta:
		author = "Elastic Security"
		id = "89e64044-74e4-4679-b6ad-bfb9b264330c"
		fingerprint = "ec45013d3ecbc39ffce5ac18d5bf8b0d18bcadd66659975b0a9f26bcae0a5b49"
		creation_date = "2021-08-06"
		last_modified = "2021-10-04"
		threat_name = "Windows.Ransomware.Lockbit"
		reference_sample = "0d6524b9a1d709ecd9f19f75fa78d94096e039b3d4592d13e8dbddf99867182d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Ransomware Lockbit variant"
		filetype = "executable"

	strings:
		$a1 = "\\LockBit_Ransomware.hta" wide fullword
		$a2 = "\\Registry\\Machine\\Software\\Classes\\Lockbit\\shell" wide fullword
		$a3 = "%s\\%02X%02X%02X%02X.lock" wide fullword

	condition:
		all of them
}
