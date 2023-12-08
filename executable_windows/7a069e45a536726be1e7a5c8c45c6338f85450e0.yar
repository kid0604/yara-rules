rule Windows_Trojan_SuddenIcon_8b07c275
{
	meta:
		author = "Elastic Security"
		id = "8b07c275-f389-4e55-bcec-4b1344cad33d"
		fingerprint = "482f1e668ab63be44a249274e0eaa167e1418c42a8f0e9e85b26e4e23ff57a0d"
		creation_date = "2023-03-29"
		last_modified = "2023-03-30"
		threat_name = "Windows.Trojan.SuddenIcon"
		reference_sample = "aa4e398b3bd8645016d8090ffc77d15f926a8e69258642191deb4e68688ff973"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan SuddenIcon"
		filetype = "executable"

	strings:
		$str1 = { 33 C9 E8 ?? ?? ?? ?? 48 8B D8 E8 ?? ?? ?? ?? 44 8B C0 B8 ?? ?? ?? ?? 41 F7 E8 8D 83 ?? ?? ?? ?? C1 FA ?? 8B CA C1 E9 ?? 03 D1 69 CA ?? ?? ?? ?? 48 8D 55 ?? 44 2B C1 48 8D 4C 24 ?? 41 03 C0 }
		$str2 = { B8 ?? ?? ?? ?? 41 BA ?? ?? ?? ?? 0F 11 84 24 ?? ?? ?? ?? 44 8B 06 8B DD BF ?? ?? ?? ?? }

	condition:
		all of them
}
