rule win_hawkball_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.hawkball."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hawkball"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? c705????????00000000 5e 6a09 6a08 ff15???????? 50 }
		$sequence_1 = { 5d c3 694508e8030000 53 56 57 6800000400 }
		$sequence_2 = { 0fb744241c 50 0fb744241e 50 0fb744241e 50 0fb7442420 }
		$sequence_3 = { 7419 83be0402000000 7e10 50 6a01 ff15???????? 50 }
		$sequence_4 = { 6a00 6a00 68???????? 6a00 ff742430 ff742438 }
		$sequence_5 = { 50 ff7311 8bcf ff730d e8???????? }
		$sequence_6 = { 55 8bec 83ec08 833d????????00 53 7460 }
		$sequence_7 = { 50 0fb745e2 50 8d85d8faffff 68???????? }
		$sequence_8 = { 8b15???????? b9???????? e8???????? 8945f8 8d8d78ffffff 51 ff15???????? }
		$sequence_9 = { 50 e8???????? 0fb745ec 68???????? 50 0fb745ea }

	condition:
		7 of them and filesize <229376
}
