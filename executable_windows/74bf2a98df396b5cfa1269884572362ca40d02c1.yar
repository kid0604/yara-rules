rule win_hakbit_auto
{
	meta:
		description = "Detect the risk of Ransomware Thanos Rule 2"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 40 c1e004 8b4dfc 8d740104 8b45e4 c1e004 8b4dfc }
		$sequence_1 = { 8bec 51 51 c745f8010000c0 e8???????? 58 }
		$sequence_2 = { 40 8945f4 837df403 7377 8b45f4 8b4dfc }
		$sequence_3 = { ff7508 8b45fc 83c018 ffd0 8945f8 837df800 0f8ca8000000 }
		$sequence_4 = { 8b4dfc 8b44810c 2b450c 8945f0 8365ec00 eb07 8b45ec }
		$sequence_5 = { 88040a ebd2 e9???????? 8b45f8 5e c9 c21400 }
		$sequence_6 = { 8364010c00 8b45e8 c1e004 8b4dfc c644010800 8b45e8 c1e004 }
		$sequence_7 = { 51 c745f8010000c0 e8???????? 58 2500f0ffff 8945fc 837d1400 }
		$sequence_8 = { 33c9 8b55fc 66894c020a 8b45e8 c1e004 8b4dfc 8364010c00 }
		$sequence_9 = { 0f8ca8000000 ff7508 8b45fc ff10 }

	condition:
		7 of them and filesize <656384
}
