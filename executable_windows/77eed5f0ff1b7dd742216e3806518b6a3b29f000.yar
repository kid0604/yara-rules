rule Windows_Trojan_SiestaGraph_ad3fe5c6
{
	meta:
		author = "Elastic Security"
		id = "ad3fe5c6-88ba-46cf-aefd-bd8ab0eff917"
		fingerprint = "653ca92d31c7212c1f154c2e18b3be095e9a39fe482ce99fbd84e19f4bf6ca64"
		creation_date = "2023-09-12"
		last_modified = "2023-09-20"
		threat_name = "Windows.Trojan.SiestaGraph"
		reference_sample = "fe8f99445ad139160a47b109a8f3291eef9c6a23b4869c48d341380d608ed4cb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects the presence of Windows Trojan SiestaGraph"
		filetype = "executable"

	strings:
		$a1 = "GetAllDriveRootChildren" ascii fullword
		$a2 = "GetDriveRoot" ascii fullword
		$a3 = "sendsession" wide fullword
		$b1 = "status OK" wide fullword
		$b2 = "upload failed" wide fullword
		$b3 = "Failed to fetch file" wide fullword
		$c1 = "Specified file doesn't exist" wide fullword
		$c2 = "file does not exist" wide fullword

	condition:
		6 of them
}
