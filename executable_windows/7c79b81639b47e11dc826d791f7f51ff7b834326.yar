rule Windows_Trojan_Generic_73ed7375
{
	meta:
		author = "Elastic Security"
		id = "73ed7375-c8ab-4d95-ae66-62b1b02a3d1e"
		fingerprint = "a026cc2db3bfebca4b4ea6e9dc41c2b18d0db730754ef3131d812d7ef9cd17d6"
		creation_date = "2023-05-09"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.Generic"
		reference_sample = "2b17328a3ef0e389419c9c86f81db4118cf79640799e5c6fdc97de0fc65ad556"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Generic"
		filetype = "executable"

	strings:
		$a1 = { 48 8B 03 48 8B CE 49 8D 54 04 02 41 FF D6 48 89 03 48 83 C3 08 48 }
		$a2 = { 41 3C 42 8B BC 08 88 00 00 00 46 8B 54 0F 20 42 8B 5C 0F 24 4D }

	condition:
		all of them
}
