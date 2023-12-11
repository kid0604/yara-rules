rule Windows_Rootkit_R77_d0367e28
{
	meta:
		author = "Elastic Security"
		id = "d0367e28-2c37-45c8-8a74-7ea881f2d471"
		fingerprint = "c3f6fe38fcc2ec40ae7c033e37f7a2830f5d53f0e796281bd484bdb65502cd0e"
		creation_date = "2023-05-18"
		last_modified = "2023-06-13"
		threat_name = "Windows.Rootkit.R77"
		reference_sample = "96849108e13172d14591169f8fdcbf8a8aa6be05b7b6ef396d65529eacc02d89"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows.Rootkit.R77"
		filetype = "executable"

	strings:
		$str0 = "service_names" wide fullword
		$str1 = "process_names" wide fullword
		$str2 = "tcp_local" wide fullword
		$str3 = "tcp_remote" wide fullword
		$str4 = "startup" wide fullword
		$str5 = "ReflectiveDllMain" ascii fullword
		$str6 = ".detourd" ascii fullword
		$binary0 = { 48 8B 10 48 8B 0B E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 57 08 48 8B 4B 08 E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 57 10 48 8B 4B 10 E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 57 18 48 8B 4B 18 E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 57 20 48 8B 4B 20 E8 ?? ?? ?? ?? 85 C0 74 ?? 48 8B 57 28 48 8B 4B 28 E8 ?? ?? ?? ?? 85 C0 }
		$binary1 = { 8B 56 04 8B 4F 04 E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 56 08 8B 4F 08 E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 56 0C 8B 4F 0C E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 56 10 8B 4F 10 E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 56 14 8B 4F 14 E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 56 18 8B 4F 18 E8 ?? ?? ?? ?? 85 C0 74 ?? 8B 56 1C 8B 4F 1C }

	condition:
		( all of ($str*)) or $binary0 or $binary1
}
