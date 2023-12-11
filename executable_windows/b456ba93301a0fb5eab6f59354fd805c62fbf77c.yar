import "pe"

rule win_coinminer_auto
{
	meta:
		description = "Detects the risk of CoinMiner Trojan rule 2"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 56 85c0 7511 e8???????? 83c404 32c0 5e }
		$sequence_1 = { e8???????? 8d8c24500b0000 8bf0 e8???????? }
		$sequence_2 = { 09c0 744a 8b5f04 48 8d8c3000700800 48 }
		$sequence_3 = { 8bf1 8b0d???????? 85ff 7527 85c9 7523 e8???????? }
		$sequence_4 = { 8bcb e8???????? 57 ff15???????? 5f b001 5b }
		$sequence_5 = { f30f6f05???????? 56 57 f30f7f442440 b920000000 be???????? f30f6f05???????? }
		$sequence_6 = { 756e 56 e8???????? 83c404 33c0 5f }
		$sequence_7 = { 6b45e430 8945e0 8d8098589000 8945e4 803800 8bc8 7435 }
		$sequence_8 = { 7314 33c0 8974241c 85f6 }
		$sequence_9 = { 83c102 ebe2 8d8df8fdffff b8???????? 90 668b10 }

	condition:
		7 of them and filesize <1523712
}
