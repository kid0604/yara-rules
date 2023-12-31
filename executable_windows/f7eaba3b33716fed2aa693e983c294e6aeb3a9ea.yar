rule win_dexbia_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.dexbia."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dexbia"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { f3a5 b918000000 8d7c2425 f3ab 66ab aa }
		$sequence_1 = { b910000000 85c0 7415 33c0 bf???????? 68???????? }
		$sequence_2 = { ffd7 55 ffd7 5f 5e 5d 33c0 }
		$sequence_3 = { 8d4c2418 51 68???????? e8???????? 8d542420 }
		$sequence_4 = { 7f0e 0fbec3 8a8054714000 83e00f eb02 }
		$sequence_5 = { 68???????? e8???????? 83c438 33c0 5f 5e 5d }
		$sequence_6 = { 6a10 52 8b08 6aff }
		$sequence_7 = { 205a40 004c5a40 00705a 40 0023 d18a0688078a }
		$sequence_8 = { f3ab 66ab aa 8b842418780000 8d4c240c }
		$sequence_9 = { 66895c2418 66899c248c000000 f3ab 66ab b981000000 }

	condition:
		7 of them and filesize <106496
}
