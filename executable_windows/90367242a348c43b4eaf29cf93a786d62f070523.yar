rule win_cerber_auto
{
	meta:
		description = "Detect the risk of Ransomware Cerber Rule 5"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { eba0 47 3bf8 0f8c3effffff 5e 5b 5f }
		$sequence_1 = { ff750c e8???????? 59 59 84c0 74e9 8d45f8 }
		$sequence_2 = { 8b4510 c6040200 4a 79f6 }
		$sequence_3 = { 237878 899804010000 8b5864 23de 8b75fc }
		$sequence_4 = { 6a00 ff36 ff15???????? bf02010000 3bc7 7561 }
		$sequence_5 = { 7508 6a03 58 e9???????? 39860c010000 }
		$sequence_6 = { 75d9 8b45f8 5f 5e 5b c9 c3 }
		$sequence_7 = { 51 8d843078030000 50 e8???????? eb1d }

	condition:
		7 of them and filesize <573440
}
