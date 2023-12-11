rule win_hotwax_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.hotwax."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hotwax"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7441 b9d0070000 ff15???????? 33d2 41b8f8000000 }
		$sequence_1 = { 4885c9 741c f0ff09 7517 488d0513ce0000 488b4c2430 483bc8 }
		$sequence_2 = { 48833d????????00 8bd9 7418 488d0dfbc00000 e8???????? 85c0 }
		$sequence_3 = { 4d03f4 4c8d442460 41b970050000 488bce 498bd6 }
		$sequence_4 = { 488bce 488bc6 488d1510ee0000 83e11f 48c1f805 486bc958 }
		$sequence_5 = { 48896c2418 56 4883ec20 498bd9 488bf2 48897c2430 488be9 }
		$sequence_6 = { 57 4881ec60010000 488b05???????? 4833c4 4889842450010000 488bf1 33ff }
		$sequence_7 = { 488bc1 48c1f805 4c8d0573710000 83e11f 486bc958 }
		$sequence_8 = { 420fbe840170300100 85c0 7513 e8???????? }
		$sequence_9 = { 488905???????? ff15???????? 488d1568d30000 488bcb 488905???????? }

	condition:
		7 of them and filesize <198656
}
