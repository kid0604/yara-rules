rule win_spyder_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.spyder."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.spyder"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 488d3da8a20000 eb0e 488b03 4885c0 7402 ffd0 4883c308 }
		$sequence_1 = { 4c8d05928a0000 8bd7 498bcd e8???????? 85c0 7415 4533c9 }
		$sequence_2 = { 0f8493010000 488d156a5f0000 488bc8 ff15???????? 4885c0 }
		$sequence_3 = { 488b03 4885c0 7437 482bfb 0f1f8000000000 4c8b4638 498bcc }
		$sequence_4 = { e8???????? 85c0 751a 488d1588890000 41b810200100 488bcd e8???????? }
		$sequence_5 = { 0f85d5000000 488d0d935f0000 ff15???????? 488bf0 4885c0 }
		$sequence_6 = { 740b b9c1000000 ff15???????? 496374243c 4903f4 813e50450000 }
		$sequence_7 = { 33d2 33c9 4889742420 e8???????? cc 4c8d05fc890000 498bd4 }
		$sequence_8 = { f7d8 83da00 5b c21000 8b542404 }
		$sequence_9 = { 8b4d0c 8a01 4a 0fb6f0 f686014a091004 }
		$sequence_10 = { 53 52 8d8424900d0000 57 50 }
		$sequence_11 = { 83e103 50 f3a4 68???????? e8???????? 8b8c2424010000 8b942428010000 }
		$sequence_12 = { 8a9405ecfdffff 889000490910 eb1c f6c202 7410 8088????????20 }
		$sequence_13 = { 0fb6fa 3bc7 7714 8b55fc 8a92783d0910 0890014a0910 40 }
		$sequence_14 = { 889c2488010000 f3ab 8b8c248c150000 8d942488010000 66ab }
		$sequence_15 = { e8???????? 83c408 8bf0 8d942488010000 46 }

	condition:
		7 of them and filesize <1458176
}
