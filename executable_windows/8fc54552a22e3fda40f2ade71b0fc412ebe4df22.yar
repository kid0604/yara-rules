rule Windows_Shellcode_Rdi_918f8e2f
{
	meta:
		author = "Elastic Security"
		id = "918f8e2f-c5b9-4fe2-9290-12a74b3b494e"
		fingerprint = "9793e0bcdf305237eb2920d54b524b1bc11c583612fc2e5190879eeed8e19663"
		creation_date = "2025-01-15"
		last_modified = "2025-02-11"
		threat_name = "Windows.Shellcode.Rdi"
		reference_sample = "d8dab346c6235426e6119f8eb6bf81cafda8fb8ea88b86205e34d9c369b3b746"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Shellcode Rdi"
		filetype = "executable"

	strings:
		$a64 = { E8 00 00 00 00 59 49 89 C8 BA ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 56 48 89 E6 48 83 E4 F0 48 83 EC 30 48 89 4C 24 28 }
		$a32 = { E8 00 00 00 00 58 55 89 E5 89 C2 81 C2 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 E8 05 00 00 00 83 C4 14 C9 C3 }

	condition:
		any of them
}
