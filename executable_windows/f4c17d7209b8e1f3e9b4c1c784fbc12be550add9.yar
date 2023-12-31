rule win_webc2_ausov_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.webc2_ausov."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_ausov"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 0f8501000000 f8 8b95f8fbffff 0355fc 8995f8fbffff 0f8407000000 }
		$sequence_1 = { 83bdc4fdffff00 7507 33c0 e9???????? 8d8da8faffff 898d4cfaffff }
		$sequence_2 = { 0f8487000000 8b3d???????? 68???????? 56 }
		$sequence_3 = { 0f8407000000 0f8501000000 f8 68???????? }
		$sequence_4 = { 83c101 894df8 8b55f8 3b55f4 7d31 0f8407000000 }
		$sequence_5 = { f7d1 83c1ff 51 8d95f8feffff 52 }
		$sequence_6 = { 0f8501000000 f8 68???????? 8d8dfcfbffff 51 }
		$sequence_7 = { 6804010000 8d85a8faffff 50 68???????? ff15???????? 8985c4fdffff 83bdc4fdffff00 }
		$sequence_8 = { 81ec10040000 53 56 57 0f8407000000 0f8501000000 }
		$sequence_9 = { e8???????? 83c404 8b4d0c 894104 e9???????? 8dbdfcfbffff 83c9ff }

	condition:
		7 of them and filesize <40960
}
