rule win_eternal_petya_auto_alt_1
{
	meta:
		description = "Detect the risk of Ransomware Petya Rule 2"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8bec 51 57 68000000f0 }
		$sequence_1 = { 68f0000000 6a40 ff15???????? 8bd8 }
		$sequence_2 = { 57 68000000f0 6a18 33ff }
		$sequence_3 = { 53 8d4644 50 53 6a02 }
		$sequence_4 = { 40 49 75f9 56 ff15???????? }
		$sequence_5 = { 53 6a21 8d460c 50 }
		$sequence_6 = { 50 8d8594f9ffff 50 894dac }
		$sequence_7 = { ff75f8 8945fc ff15???????? 56 56 6a02 56 }
		$sequence_8 = { ff7608 03c1 50 ff15???????? }
		$sequence_9 = { 0fb7044a 6685c0 7412 0fb7444584 66890c47 0fb7044a 66ff444584 }
		$sequence_10 = { 83e001 89412c 8b4320 c7403001000000 }
		$sequence_11 = { 8b4d0c 0fb71441 8955f0 3bd3 0f862fffffff 8b45cc }
		$sequence_12 = { 2bc1 d1f8 8d440002 50 6a08 ffd6 50 }
		$sequence_13 = { 83e001 894304 8bc2 83e003 83e800 }
		$sequence_14 = { 75f5 2bcf d1f9 8d1409 8bce 85d2 }
		$sequence_15 = { 50 ffd6 85c0 0f8480000000 8b95f4fdffff 8d8df8fdffff }

	condition:
		7 of them and filesize <851968
}
