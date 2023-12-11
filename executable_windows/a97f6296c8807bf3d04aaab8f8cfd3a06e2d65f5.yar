rule BITS_CLSID
{
	meta:
		description = "References the BITS service."
		author = "Ivan Kwiatkowski (@JusticeRage)"
		os = "windows"
		filetype = "executable"

	strings:
		$uuid_background_copy_manager_1_5 = { 1F 77 87 F0 4F D7 1A 4C BB 8A E1 6A CA 91 24 EA }
		$uuid_background_copy_manager_2_0 = { 12 AD 18 6D E3 BD 93 43 B3 11 09 9C 34 6E 6D F9 }
		$uuid_background_copy_manager_2_5 = { D6 98 CA 03 5D FF B8 49 AB C6 03 DD 84 12 70 20 }
		$uuid_background_copy_manager_3_0 = { A7 DE 9C 65 9E 48 D9 11 A9 CD 00 0D 56 96 52 51 }
		$uuid_background_copy_manager_4_0 = { 6B F5 6D BB CE CA DC 11 99 92 00 19 B9 3A 3A 84 }
		$uuid_background_copy_manager_5_0 = { 4C A3 CC 1E 8A E8 E3 44 8D 6A 89 21 BD E9 E4 52 }
		$uuid_background_copy_manager = { 4B D3 91 49 A1 80 91 42 83 B6 33 28 36 6B 90 97 }
		$uuid_ibackground_copy_manager = { 0D 4C E3 5C C9 0D 1F 4C 89 7C DA A1 B7 8C EE 7C }
		$uuid_background_copy_qmanager = { 69 AD 4A EE 51 BE 43 9B A9 2C 86 AE 49 0E 8B 30 }
		$uuid_ibits_peer_cache_administration = { AD DE 9C 65 9E 48 D9 11 A9 CD 00 0D 56 96 52 51 }
		$uuid_background_copy_callback = { C7 99 EA 97 86 01 D4 4A 8D F9 C5 B4 E0 ED 6B 22 }

	condition:
		any of them
}
