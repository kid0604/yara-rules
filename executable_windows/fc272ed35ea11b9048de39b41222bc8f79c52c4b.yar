rule win_bolek_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.bolek."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bolek"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { eb10 0fb603 50 ff15???????? 59 85c0 7405 }
		$sequence_1 = { 0fa4cb08 99 c1e108 0bda 0bc8 0fb64631 0fa4cb08 }
		$sequence_2 = { 8bf0 c1e608 0fb601 03f0 8d442414 41 50 }
		$sequence_3 = { c1e710 0bf8 0fb64301 99 81e7ffffff03 25ffff0300 0fa4c108 }
		$sequence_4 = { 85c0 0f8440010000 ff74241c ffd3 ff742418 33ff 897c2420 }
		$sequence_5 = { 8bcf e8???????? 85c0 742d 8d95e87fffff 8bcb e8???????? }
		$sequence_6 = { ff7310 e8???????? 83c434 8d9578ffffff 8d8d50ffffff 6aff e8???????? }
		$sequence_7 = { eb40 56 ff750c 8d45f4 50 68???????? ff7508 }
		$sequence_8 = { 894c2414 50 ff762c ff7628 e8???????? 83c410 85c0 }
		$sequence_9 = { eb07 83f91e 7709 8bcb 46 3bf7 72d2 }

	condition:
		7 of them and filesize <892928
}
