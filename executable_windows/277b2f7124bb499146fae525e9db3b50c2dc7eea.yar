rule win_molerat_loader_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.molerat_loader."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.molerat_loader"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 50 8b4204 ffd0 c645fc0a 8b45e8 83c0f0 }
		$sequence_1 = { ff15???????? 5d c20400 c20400 6a00 }
		$sequence_2 = { 8b4204 ffd0 837de401 7f05 e8???????? 8b45e0 }
		$sequence_3 = { 8d5588 52 c645fc18 e8???????? 8b00 8b35???????? }
		$sequence_4 = { e8???????? 8b4d58 e8???????? 8d4d28 e8???????? 8d4d08 e9???????? }
		$sequence_5 = { 8bff 55 8bec 8b4508 33c9 3b04cdf03d4400 7413 }
		$sequence_6 = { c645fc32 e8???????? 68???????? 8d4db4 c645fc33 e8???????? }
		$sequence_7 = { c645fc08 e8???????? 8b4540 83c0f0 83caff 8d480c }
		$sequence_8 = { 68???????? e8???????? e8???????? 83c404 8d4d00 e8???????? 8b5578 }
		$sequence_9 = { 8d4c2410 56 51 e8???????? 83c40c b302 }

	condition:
		7 of them and filesize <688128
}
