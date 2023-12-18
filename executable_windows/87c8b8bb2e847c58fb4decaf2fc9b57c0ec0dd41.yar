rule win_newpass_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.newpass."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.newpass"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 4d8bc4 eb0f 4983c8ff 49ffc0 6642833c4700 75f5 488bd7 }
		$sequence_1 = { 488d542470 48837d8810 480f43542470 488b5910 4883791810 7203 }
		$sequence_2 = { 85c0 792e 488b842490000000 4889442428 4c8bce 440fb6c7 488d542470 }
		$sequence_3 = { eb09 418bc7 493bf6 0f95c0 85c0 7906 488b7f10 }
		$sequence_4 = { 7503 488b07 483bc8 741b 448bc2 488bd0 e8???????? }
		$sequence_5 = { c7411006160000 8b4110 0f49c2 488939 894110 b001 }
		$sequence_6 = { 488bcb e8???????? 84c0 753d 488bcb e8???????? 3a4500 }
		$sequence_7 = { 4c0f44ca 41397920 7340 498b4110 488bd3 498bca }
		$sequence_8 = { 7410 4c8bce 488bc8 e8???????? 488bd8 eb03 498bdd }
		$sequence_9 = { 807a1900 7525 488bc2 488b12 807a1900 7539 6666660f1f840000000000 }

	condition:
		7 of them and filesize <2654208
}
