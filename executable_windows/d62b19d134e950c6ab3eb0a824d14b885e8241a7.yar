rule win_chaperone_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.chaperone."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chaperone"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 488b8424a0050000 488914c8 488b8424b8050000 8b00 83e801 4898 488d542430 }
		$sequence_1 = { 488d542440 488b8c2498070000 e8???????? 488d542440 488d8c24a0020000 ff15???????? 66ba5c00 }
		$sequence_2 = { e8???????? 85c0 742d 488d0567a70100 4883c310 }
		$sequence_3 = { ff15???????? 85c0 750a c744243001000000 eb02 eb9e 837c243000 }
		$sequence_4 = { e8???????? 488d7c2428 488d35eb9a0000 b91e000000 f3a4 }
		$sequence_5 = { b92e000000 f3a4 488dbc2488020000 488d35f8c40100 b926000000 f3a4 }
		$sequence_6 = { c6442457d0 c644245820 c644245902 c644245a15 }
		$sequence_7 = { e8???????? c744242000000000 eb0b 8b442420 83c001 89442420 }
		$sequence_8 = { 488b8c24a0010000 ff15???????? 488905???????? 488d942480020000 488b8c24a0010000 ff15???????? 488905???????? }
		$sequence_9 = { 83bc247002000000 7419 488b542430 4881c238020000 488b4c2420 ff15???????? }

	condition:
		7 of them and filesize <373760
}