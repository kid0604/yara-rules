rule win_beepservice_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.beepservice."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.beepservice"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 68???????? ffd6 8bc8 ff15???????? 50 ff15???????? }
		$sequence_1 = { 683f000f00 6a00 68???????? ff15???????? }
		$sequence_2 = { 83f801 7505 e8???????? 68???????? 68???????? }
		$sequence_3 = { ff15???????? 50 68???????? e8???????? 83c408 e9???????? 68???????? }
		$sequence_4 = { 83c408 e9???????? 68???????? e8???????? 83c404 6a00 }
		$sequence_5 = { 7512 6888130000 68???????? e8???????? }
		$sequence_6 = { e8???????? 59 59 ff761c e8???????? 83f820 }
		$sequence_7 = { ff7608 e8???????? 50 ff7608 68???????? e8???????? 83c444 }
		$sequence_8 = { 750e ff15???????? 50 68???????? eb43 56 8d45fc }
		$sequence_9 = { 83f820 59 730f ff7618 68???????? }
		$sequence_10 = { 50 ff15???????? 83c410 33f6 8d85fcfdffff 56 56 }
		$sequence_11 = { e8???????? ff7610 e8???????? 50 }
		$sequence_12 = { e8???????? 50 ff7614 57 e8???????? 83c42c e8???????? }
		$sequence_13 = { f3a4 8b531c 83c9ff 8bfa 33c0 f2ae }
		$sequence_14 = { a3???????? 83c404 a3???????? a3???????? 66a3???????? f3ab b908000000 }
		$sequence_15 = { 49 83f920 7320 8bfa 83c9ff }
		$sequence_16 = { ffd7 8d442414 50 56 }
		$sequence_17 = { ff15???????? 8985d4fdffff 83bdd4fdffff00 7516 ff15???????? 50 68???????? }
		$sequence_18 = { eb0f 8b95f8fdffff 83c201 8995f8fdffff 83bdf8fdffff0a }
		$sequence_19 = { e9???????? 8b550c 8b4210 50 e8???????? 83c404 83f826 }
		$sequence_20 = { 81c428010000 c3 5f 5e 33c0 5b }
		$sequence_21 = { 7ced b90a000000 be???????? bf???????? 33c0 }
		$sequence_22 = { 7403 50 ffd6 a1???????? 85c0 7415 }
		$sequence_23 = { 6a00 6a00 51 e8???????? 83c414 c3 }
		$sequence_24 = { 8b45e4 85c0 7407 50 ff15???????? 85ff }
		$sequence_25 = { 6a01 e8???????? 83c414 a1???????? 85c0 7403 50 }
		$sequence_26 = { 6a00 6a00 57 ff15???????? 8945e4 85c0 }
		$sequence_27 = { 8a8228304000 3c39 7f04 3c30 7d02 32db }

	condition:
		7 of them and filesize <253952
}
