rule Linux_Trojan_Xorddos_a6572d63
{
	meta:
		author = "Elastic Security"
		id = "a6572d63-f9f3-4dfb-87e6-3b0bafd68a79"
		fingerprint = "fd32a773785f847cdd59d41786a8d8a7ba800a71d40d804aca51286d9bb1e1f0"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "2ff33adb421a166895c3816d506a63dff4e1e8fa91f2ac8fb763dc6e8df59d6e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Trojan.Xorddos malware"
		filetype = "executable"

	strings:
		$a = { C8 0F B6 46 04 0F B6 56 05 C1 E0 08 09 D0 89 45 CC 0F B6 46 06 0F B6 }

	condition:
		all of them
}
