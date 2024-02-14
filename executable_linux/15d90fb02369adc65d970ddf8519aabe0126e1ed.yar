rule Linux_Ransomware_Lockbit_5b30a04b
{
	meta:
		author = "Elastic Security"
		id = "5b30a04b-d618-4698-a797-30bf6d4a001c"
		fingerprint = "99bf6afb1554ec3b3b82389c93ca87018c51f7a80270d64007a5f5fc59715c45"
		creation_date = "2023-07-29"
		last_modified = "2024-02-13"
		threat_name = "Linux.Ransomware.Lockbit"
		reference_sample = "41cbb7d79388eaa4d6e704bd4a8bf8f34d486d27277001c343ea3ce112f4fb0d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Ransomware.Lockbit ransomware"
		filetype = "executable"

	strings:
		$a1 = { 5D 50 4A 49 55 58 40 77 58 54 5C }
		$a2 = { 33 6B 5C 5A 4C 4B 4A 50 4F 5C 55 40 }
		$a3 = { 5E 4C 58 4B 58 57 4D 5C 5C 5D }

	condition:
		all of them
}
