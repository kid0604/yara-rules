rule win_concealment_troy_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.concealment_troy."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.concealment_troy"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c1f905 8d1c8da0774100 8bf8 83e71f c1e706 8b0b }
		$sequence_1 = { 8bc2 0aff 74df 8b8d90000000 }
		$sequence_2 = { 83c40c c744240800000000 85f6 743b 8b16 }
		$sequence_3 = { 33c4 89842420010000 8b842428010000 56 57 8944240c 33c0 }
		$sequence_4 = { 837ddc00 75e6 c6460401 830eff 2b34bda0774100 c1fe06 }
		$sequence_5 = { 33db 83c408 3bf3 751a }
		$sequence_6 = { 51 ff15???????? 0fb745d8 99 b964000000 f7f9 0fb745de }
		$sequence_7 = { 8d842420010000 e8???????? 8d542418 8d9b00000000 8a08 880a }
		$sequence_8 = { 8d44242c 57 50 e8???????? 57 8d8c243c010000 }
		$sequence_9 = { 8d942468020000 83c40c 8bc6 2bd6 }

	condition:
		7 of them and filesize <229376
}
