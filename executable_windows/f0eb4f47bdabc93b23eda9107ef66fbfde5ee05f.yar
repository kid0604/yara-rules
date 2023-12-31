rule win_pillowmint_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.pillowmint."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pillowmint"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? b001 eb43 48837de710 720a 488b4dcf }
		$sequence_1 = { 488bcb 488905???????? ff15???????? 488d159f970100 483305???????? 488bcb 488905???????? }
		$sequence_2 = { 8bf9 0f8586000000 488bca e8???????? 4c8d0da8df0200 4c8d1db1ff0200 4c63d0 }
		$sequence_3 = { 5f 5e 5b c3 488d0dd93f0300 e8???????? }
		$sequence_4 = { 488d4c2460 e8???????? 90 488d0d4e280400 ff15???????? }
		$sequence_5 = { c705????????01000000 b808000000 486bc000 488d0d42e30200 48c7040102000000 b808000000 486bc000 }
		$sequence_6 = { 488bf9 e8???????? 488d05bcf10200 488907 488d05caf10200 0f104318 488b5c2430 }
		$sequence_7 = { 754d 33d2 41b800800000 488bcb ff15???????? 8b05???????? 33c9 }
		$sequence_8 = { 488bf9 4c8bca 4c8d0505650300 488d4c2430 8d5340 895c2420 e8???????? }
		$sequence_9 = { 33c9 ff15???????? 488bc8 e8???????? 90 4883bc24f800000010 720d }

	condition:
		7 of them and filesize <4667392
}
