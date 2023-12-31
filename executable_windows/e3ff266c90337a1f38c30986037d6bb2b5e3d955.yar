rule win_whispergate_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.whispergate."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.whispergate"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 894dc4 0f8556030000 8965a8 891c24 e8???????? }
		$sequence_1 = { 31db e9???????? b83f000000 e9???????? b85b000000 e9???????? 8d5d03 }
		$sequence_2 = { 740a 6683f95c 0f8597feffff 0fb74de2 }
		$sequence_3 = { 83ea01 85d2 c7049100000000 75f2 31c0 }
		$sequence_4 = { 8b35???????? 85f6 0f858f000000 8b1d???????? 85db 0f8581000000 8b0d???????? }
		$sequence_5 = { e8???????? 85c0 75cd 0fb75606 }
		$sequence_6 = { 89c3 83ec6c 8955d0 80e604 894dc4 }
		$sequence_7 = { a1???????? 8955e4 890424 e8???????? 8b55e4 a3???????? 89c6 }
		$sequence_8 = { 8b7dbc 8d5f04 89f8 8b00 }
		$sequence_9 = { 7275 8b45d0 85c0 756e 89fa 31c0 }

	condition:
		7 of them and filesize <114688
}
