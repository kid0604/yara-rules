rule Windows_Hacktool_Mimikatz_1ff74f7e
{
	meta:
		author = "Elastic Security"
		id = "1ff74f7e-ec5a-45ae-b51b-2f8205445cc8"
		fingerprint = "6775be439ad1822bcaa04ed2d392143616746cfd674202aa29773c98642346f4"
		creation_date = "2023-05-09"
		last_modified = "2023-06-13"
		threat_name = "Windows.Hacktool.Mimikatz"
		reference_sample = "1b6aad500d45de7b076942d31b7c3e77487643811a335ae5ce6783368a4a5081"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows.Hacktool.Mimikatz"
		filetype = "executable"

	strings:
		$a1 = { 74 65 48 8B 44 24 28 0F B7 80 E0 00 00 00 83 F8 10 75 54 48 8B 44 }
		$a2 = { 74 69 48 8B 44 24 28 0F B7 80 D0 00 00 00 83 F8 10 75 58 48 8B 44 }

	condition:
		all of them
}
