import "hash"

rule win_darkside_auto
{
	meta:
		description = "Detect the risk of Ransomeware Darkside Rule 7"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 12d2 13c0 7406 8bdf }
		$sequence_1 = { 12d2 73e6 02d2 7505 8a16 46 }
		$sequence_2 = { 83c701 bb02000000 02d2 7505 8a16 46 12d2 }
		$sequence_3 = { b9f0000000 be???????? 8b4508 8b10 }
		$sequence_4 = { 8b7808 8b400c 89540e0c 89440e08 895c0e04 893c0e }
		$sequence_5 = { 81c7ff000000 4b 85db 75ea }
		$sequence_6 = { 33db fec1 75d2 5f 5e 5a }
		$sequence_7 = { 8b5804 8b7808 8b400c 89540e0c 89440e08 895c0e04 893c0e }
		$sequence_8 = { 85c0 7418 8bd8 68ff000000 57 e8???????? 81c7ff000000 }
		$sequence_9 = { 5b 5d c20c00 55 8bec 53 51 }

	condition:
		7 of them and filesize <286720
}
