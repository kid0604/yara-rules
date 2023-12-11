rule win_cobalt_sleep_encrypt
{
	meta:
		author = "Matthew @ Embee_Research"
		created = "2023/08/27"
		description = "Detects Sleep Encryption Logic Found in Cobalt Strike Deployments"
		sha_256 = "26b2f12906c3590c8272b80358867944fd86b9f2cc21ee6f76f023db812e5bb1"
		os = "windows"
		filetype = "executable"

	strings:
		$r1_nokey = {4E 8B 04 08 B8 ?? ?? ?? ?? 41 F7 E3 41 8B C3 C1 EA 02 41 FF C3 6B D2 0D 2B C2 8A 4C 18 18 41 30 0C 38 48 8B 43 10 41 8B FB 4A 3B 7C 08 08}
		$r2_nokey = {49 8B F9 4C 8B 03 B8 ?? ?? ?? ?? 41 F7 E1 41 8B C1 C1 EA 02 41 FF C1 6B D2 0D 2B C2 8A 4C 18 18 42 30 0C 07 48 FF C7 45 3B CB}

	condition:
		($r1_nokey or $r2_nokey)
}
