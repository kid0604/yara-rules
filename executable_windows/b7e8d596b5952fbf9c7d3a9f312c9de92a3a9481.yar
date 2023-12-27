rule win_lumma_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.lumma."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lumma"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 57 53 ff767c ff7678 }
		$sequence_1 = { 53 49 83fc00 75e8 8b4508 49 89ca }
		$sequence_2 = { e8???????? ff7614 e8???????? ff7608 e8???????? 83c414 83c8ff }
		$sequence_3 = { 4d 6be404 49 83ec04 }
		$sequence_4 = { 41 5b 41 5c }
		$sequence_5 = { c1e002 50 e8???????? 894614 8b461c c1e002 }
		$sequence_6 = { 0fb64203 83c204 33c1 c1e908 }
		$sequence_7 = { 41 5a cb 55 89e5 8b550c }
		$sequence_8 = { 4d 6bdb08 4c 01dc }
		$sequence_9 = { 50 e8???????? 894604 8b461c }
		$sequence_10 = { 41 8b0a 41 8b5204 }
		$sequence_11 = { 4d 89f3 49 83eb04 }
		$sequence_12 = { 57 8bf2 8bd9 6a2e 56 }
		$sequence_13 = { 03c0 3bc2 0f47d0 e8???????? 85c0 }
		$sequence_14 = { c1e002 50 e8???????? 89460c 8b461c c1e002 }

	condition:
		7 of them and filesize <838656
}