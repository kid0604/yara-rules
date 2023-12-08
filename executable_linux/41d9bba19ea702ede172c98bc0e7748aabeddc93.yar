rule Linux_Trojan_Generic_378765e4
{
	meta:
		author = "Elastic Security"
		id = "378765e4-c0f2-42ad-a42b-b992d3b866f4"
		fingerprint = "60f259ba5ffe607b594c2744b9b30c35beab9683f4cd83c2e31556a387138923"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Generic"
		reference_sample = "1ed42910e09e88777ae9958439d14176cb77271edf110053e1a29372fce21ec1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic Linux Trojan"
		filetype = "executable"

	strings:
		$a = { E8 ?? FB FF FF 83 7D D4 00 79 0A B8 ?? 22 60 00 }

	condition:
		all of them
}
