rule win_hyperbro_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.hyperbro."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hyperbro"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83c410 52 c7460840000000 c7460402000000 }
		$sequence_1 = { ff15???????? 53 8d4c240c 51 8d5618 894604 }
		$sequence_2 = { 8b462c c706???????? 85c0 7410 50 e8???????? }
		$sequence_3 = { 83c404 5f 5e c7450000000000 5d c70200000000 }
		$sequence_4 = { 8b5710 52 e8???????? 8b470c 50 e8???????? }
		$sequence_5 = { 8bff 05ff000000 41 3d01feffff 0f878c010000 8bd5 2bd1 }
		$sequence_6 = { 8944242c 89442440 c744243003000000 e8???????? 83c404 6882000000 56 }
		$sequence_7 = { 89442458 7d09 3d33270000 7504 }
		$sequence_8 = { 893e 894608 eb09 8b16 03d1 }
		$sequence_9 = { 52 8d7c2418 e8???????? 68???????? 8bc7 50 e8???????? }

	condition:
		7 of them and filesize <352256
}
