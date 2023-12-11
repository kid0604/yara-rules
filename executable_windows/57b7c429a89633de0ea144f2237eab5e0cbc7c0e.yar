rule Windows_Trojan_Generic_4fbff084
{
	meta:
		author = "Elastic Security"
		id = "4fbff084-5280-4ff8-9c21-c437207231a5"
		fingerprint = "728d7877e7a16fbb756b1c3b6c90ff3b718f0f750803b6a1549cb32c69be0dfc"
		creation_date = "2023-02-28"
		last_modified = "2023-04-23"
		description = "Shellcode found in REF2924, belonging to for now unknown trojan"
		threat_name = "Windows.Trojan.Generic"
		reference_sample = "7010a69ba77e65e70f4f3f4a10af804e6932c2218ff4abd5f81240026822b401"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$string_decryption = { 8A 44 30 ?? 8A CD 88 45 ?? 32 C5 C0 C1 ?? 88 04 3E 0F B6 C5 0F B6 D9 0F AF D8 0F B6 C1 0F B6 D1 88 6D ?? 0F AF D0 0F B6 C5 0F B6 CD 0F AF C8 8A 6D ?? 8A 45 ?? C0 CB ?? 02 D1 32 DA 02 EB 88 6D ?? 38 45 ?? 74 ?? 8B 45 ?? 46 81 FE ?? ?? ?? ?? 7C ?? }
		$thread_start = { E8 ?? ?? ?? ?? 6A ?? 8D 44 24 ?? BB ?? ?? ?? ?? 50 6A ?? 5A 8B CF 89 5C 24 ?? E8 ?? ?? ?? ?? 6A ?? 8D 44 24 ?? 89 5C 24 ?? 50 6A ?? 5A 8B CF E8 ?? ?? ?? ?? 6A ?? 8D 44 24 ?? 89 5C 24 ?? 50 6A ?? 5A 8B CF E8 ?? ?? ?? ?? 6A ?? 8D 44 24 ?? 89 5C 24 ?? 50 6A ?? 5A 8B CF E8 ?? ?? ?? ?? }
		$resolve = { 8B 7A ?? 8D 5D ?? 85 FF 74 ?? 0F B7 0F 8D 7F ?? 8D 41 ?? 83 F8 ?? 77 ?? 83 C1 ?? 0F B7 33 83 C3 ?? 8D 46 ?? 83 F8 ?? 77 ?? 83 C6 ?? 85 C9 }

	condition:
		2 of them
}
