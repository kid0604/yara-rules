rule Windows_Ransomware_Makop_3e388338
{
	meta:
		author = "Elastic Security"
		id = "3e388338-83c7-453c-b865-13f3bd059515"
		fingerprint = "7920469120a69fed191c5068739ed922dcf67aa26d68e44708a1d63dc0931bc3"
		creation_date = "2021-08-05"
		last_modified = "2021-10-04"
		threat_name = "Windows.Ransomware.Makop"
		reference_sample = "854226fc4f5388d40cd9e7312797dd63739444d69a67e4126ef60817fa6972ad"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Ransomware Makop"
		filetype = "executable"

	strings:
		$a1 = "MPR.dll" ascii fullword
		$a2 = "\"%s\" n%u" wide fullword
		$a3 = "\\\\.\\%c:" wide fullword
		$a4 = "%s\\%s\\%s" wide fullword
		$a5 = "%s\\%s" wide fullword
		$a6 = "Start folder" wide fullword

	condition:
		all of them
}
