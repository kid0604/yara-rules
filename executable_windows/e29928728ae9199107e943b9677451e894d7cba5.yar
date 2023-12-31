rule win_cycbot_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.cycbot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cycbot"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b8580deffff e8???????? 83c410 ff7518 81c3240f0000 53 898584deffff }
		$sequence_1 = { 8bc1 8b7dec c6043000 47 897dec 83ff03 0f8c52ffffff }
		$sequence_2 = { 8b048560544400 68???????? 50 e8???????? 59 85c0 a1???????? }
		$sequence_3 = { ffb5b4fdffff 8985e8feffff 8b4510 ffb5bcfdffff 8985d0feffff 8d85c4fdffff 50 }
		$sequence_4 = { 59 eb28 ff15???????? 50 ffb5a0fbffff 8d45c4 }
		$sequence_5 = { 50 68???????? ebc2 50 ff15???????? 8945dc }
		$sequence_6 = { 8bc6 5b c9 c20c00 68???????? e8???????? cc }
		$sequence_7 = { 837dd020 8975cc 7c97 8b45c8 3bc3 740c 3b45c4 }
		$sequence_8 = { 33149d608d4300 8bd8 c1eb18 33149d60854300 25ff000000 33148560914300 3351fc }
		$sequence_9 = { 8b442458 59 6a00 56 8d4c245c 51 50 }

	condition:
		7 of them and filesize <1163264
}
