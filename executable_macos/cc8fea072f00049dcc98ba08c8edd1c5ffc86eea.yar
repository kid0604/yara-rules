rule MacOS_Trojan_Bundlore_75c8cb4e
{
	meta:
		author = "Elastic Security"
		id = "75c8cb4e-f8bd-4a2c-8a5e-8500e12a9030"
		fingerprint = "db68c315dba62f81168579aead9c5827f7bf1df4a3c2e557b920fa8fbbd6f3c2"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Bundlore"
		reference_sample = "3d69912e19758958e1ebdef5e12c70c705d7911c3b9df03348c5d02dd06ebe4e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS Trojan Bundlore variant"
		filetype = "executable"

	strings:
		$a = { 35 EE 19 00 00 EA 80 35 E8 19 00 00 3B 80 35 E2 19 00 00 A4 80 35 DC 19 00 00 }

	condition:
		all of them
}
