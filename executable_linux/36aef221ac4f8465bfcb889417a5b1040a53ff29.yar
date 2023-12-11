rule Linux_Trojan_Xorddos_0eb147ca
{
	meta:
		author = "Elastic Security"
		id = "0eb147ca-ec6d-4a6d-b807-4de8c1eff875"
		fingerprint = "6a1667f585a7bee05d5aece397a22e376562d2b264d3f287874e5a1843e67955"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "45f25d2ffa2fc2566ed0eab6bdaf6989006315bbbbc591288be39b65abf2410b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos"
		filetype = "executable"

	strings:
		$a = { 83 45 F0 01 8B 45 F0 89 45 E8 8B 45 E8 83 C4 18 5F 5D C3 55 }

	condition:
		all of them
}
