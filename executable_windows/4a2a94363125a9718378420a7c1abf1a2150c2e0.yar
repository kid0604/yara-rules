rule Windows_Trojan_BruteRatel_ade6c9d5
{
	meta:
		author = "Elastic Security"
		id = "ade6c9d5-e9b5-4ef8-bacd-2f050c25f7f6"
		fingerprint = "9a4c5660eeb9158652561cf120e91ea5887841ed71f69e7cf4bfe4cfb11fe74a"
		creation_date = "2023-01-24"
		last_modified = "2023-02-01"
		description = "Targets API hashes used by BruteRatel"
		threat_name = "Windows.Trojan.BruteRatel"
		reference_sample = "dc9757c9aa3aff76d86f9f23a3d20a817e48ca3d7294307cc67477177af5c0d4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$c1_NtReadVirtualMemory = { AA A5 EF 3A }
		$c2_NtQuerySystemInformation = { D6 CA E1 E4 }
		$c3_NtCreateFile = { 9D 8F 88 03 }
		$c4_RtlSetCurrentTranscation = { 90 85 A3 99 }
		$c5_LoadLibrary = { 8E 4E 0E EC }

	condition:
		all of them
}
