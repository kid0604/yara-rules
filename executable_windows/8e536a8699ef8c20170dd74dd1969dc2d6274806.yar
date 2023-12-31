rule win_predator_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.predator."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.predator"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 03c2 8bce 50 e8???????? }
		$sequence_1 = { 3bcf 0f42f9 83781410 7202 8b00 57 }
		$sequence_2 = { 56 ff750c 8bf1 8d4dfd ff7508 }
		$sequence_3 = { 59 8bc3 eb1b 43 }
		$sequence_4 = { 50 8bcf e8???????? e9???????? 0f2805???????? }
		$sequence_5 = { 895dfc ff7514 8b4d10 e8???????? }
		$sequence_6 = { 57 03c2 8bce 50 }
		$sequence_7 = { 8bc2 56 8bf1 8d4dfd 57 6a0a }
		$sequence_8 = { 56 57 8965f0 8365fc00 0f2805???????? }
		$sequence_9 = { 8965f0 8365fc00 8b7508 8b450c 33c9 0fa2 }

	condition:
		7 of them and filesize <2211840
}
