rule Linux_Trojan_Generic_f657fb4f
{
	meta:
		author = "Elastic Security"
		id = "f657fb4f-a065-4d51-bead-fd28f8053418"
		fingerprint = "8c15d5e53b95002f569d63c91db7858c4ca8f26c441cb348a1b34f3b26d02468"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Generic"
		reference_sample = "1ed42910e09e88777ae9958439d14176cb77271edf110053e1a29372fce21ec1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Generic with fingerprint f657fb4f"
		filetype = "executable"

	strings:
		$a = { E8 ?? FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }

	condition:
		all of them
}
