rule win_rorschach_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.rorschach."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rorschach"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 8885df000000 33d2 488d8da0000000 e8???????? 8885e0000000 b26d }
		$sequence_1 = { 488bf0 400fb6d7 488d4dc8 e8???????? 8806 49ffc6 4983fe0e }
		$sequence_2 = { e9???????? 0fb75106 8915???????? 0fb77914 4803f9 488b0d???????? 4885c9 }
		$sequence_3 = { e8???????? 8885d1070000 33d2 488d8dd0060000 e8???????? 8885d2070000 b222 }
		$sequence_4 = { 0fb64db0 ebed 66c745bd0000 488b8da8000000 4903cf 488d55b1 e8???????? }
		$sequence_5 = { e8???????? 8885fa020000 b26e 488d8dd0020000 e8???????? 8885fb020000 33d2 }
		$sequence_6 = { e8???????? 8885c00b0000 b265 488d8d300b0000 e8???????? 8885c10b0000 33d2 }
		$sequence_7 = { eb0f 488bd3 488d0dff6c0300 e8???????? 33c9 85c0 480f44cb }
		$sequence_8 = { 4983ff12 72c1 ba12000000 488d8d91000000 e8???????? c60000 ba13000000 }
		$sequence_9 = { e8???????? 8885ee090000 b273 488d8de0080000 e8???????? 8885ef090000 33d2 }

	condition:
		7 of them and filesize <3921930
}
