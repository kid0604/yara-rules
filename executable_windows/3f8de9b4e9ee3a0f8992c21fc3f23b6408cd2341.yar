rule win_obscene_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.obscene."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.obscene"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6a06 68fc421010 ff35???????? 6aff ff15???????? ff7520 }
		$sequence_1 = { 68e4401010 e8???????? 59 80a0e240101000 68e4401010 e8???????? 59 }
		$sequence_2 = { 59 6820431010 68e4401010 e8???????? 59 59 85c0 }
		$sequence_3 = { 0fbe00 83f809 7416 8b45fc 0fbe00 83f80d }
		$sequence_4 = { 59 80a012109a0000 68???????? e8???????? }
		$sequence_5 = { 50 e8???????? 59 68???????? 8d85ecf6ffff 50 }
		$sequence_6 = { 8bec b8400d0300 e8???????? 68360d0300 ff7508 }
		$sequence_7 = { 59 59 68c4501010 68d83f1010 6814110010 e8???????? }
		$sequence_8 = { 0fbe00 83f82d 7409 8b45f8 40 8945f8 eb08 }
		$sequence_9 = { 8365fc00 6a40 ff7508 ff15???????? 59 59 }

	condition:
		7 of them and filesize <2170880
}