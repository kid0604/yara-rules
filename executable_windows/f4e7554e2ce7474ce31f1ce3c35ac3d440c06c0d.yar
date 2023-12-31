rule win_malumpos_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.malumpos."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.malumpos"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 85f6 7907 0d80000000 eb27 }
		$sequence_1 = { 53 50 c78500fdffff07000100 895d4c 895dcc e8???????? }
		$sequence_2 = { 59 8d45cc 50 ff15???????? 6a44 }
		$sequence_3 = { 0f1f00 0f1f00 0f1f00 0f1f00 6a72 }
		$sequence_4 = { 3bc8 0f86f1feffff ff770c 50 e8???????? }
		$sequence_5 = { 7805 0500000000 57 3500000000 }
		$sequence_6 = { 8a0432 3c3d 7506 8365fc00 eb0d }
		$sequence_7 = { e8???????? 68???????? a3???????? ffd0 810d????????00200000 be???????? c745f468e50300 }
		$sequence_8 = { 6683f300 55 51 7204 }
		$sequence_9 = { 8d4520 50 ff15???????? 8d4520 }

	condition:
		7 of them and filesize <542720
}
