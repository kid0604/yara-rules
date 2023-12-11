rule Linux_Trojan_Generic_d3fe3fae
{
	meta:
		author = "Elastic Security"
		id = "d3fe3fae-f7ec-48d5-8b17-9ab11a5b689f"
		fingerprint = "1773a3e22cb44fe0b3e68d343a92939a955027e735c60b48cf3b7312ce3a6415"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Generic"
		reference_sample = "2a2542142adb05bff753e0652e119c1d49232d61c49134f13192425653332dc3"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Generic with fingerprint d3fe3fae"
		filetype = "executable"

	strings:
		$a = { 47 53 45 54 2C 20 70 69 64 2C 20 4E 54 5F 50 52 53 54 41 54 }

	condition:
		all of them
}
