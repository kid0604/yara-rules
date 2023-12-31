rule win_xorist_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.xorist."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xorist"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 43 8a042a 88040a 8d567c 8b02 8baedce60000 }
		$sequence_1 = { eb02 33c0 88049dc15d4400 88049dc0594400 88049dc3554400 88049dc2514400 88048dc16d4400 }
		$sequence_2 = { 55 b9???????? e8???????? 5d 5f 5e 8ac3 }
		$sequence_3 = { 6bc70b 5f 8d1491 0fb74d02 3bc8 1bc0 83e002 }
		$sequence_4 = { 5e 741f 83fdff 741a 834c2410ff 8d442410 834c2414ff }
		$sequence_5 = { 3bc7 74df 5f 8be5 5d c20400 55 }
		$sequence_6 = { 6a1a 59 8db424fc000000 8bfd f3a5 c60001 6a20 }
		$sequence_7 = { 50 6a00 ff15???????? 33c0 50 50 6a03 }
		$sequence_8 = { eb02 b001 c20400 57 8b7c2414 85ff 742d }
		$sequence_9 = { e8???????? 8b865c4c0000 3b864c4c0000 0f8f3c050000 7c12 8b86584c0000 3b86484c0000 }

	condition:
		7 of them and filesize <1402880
}
