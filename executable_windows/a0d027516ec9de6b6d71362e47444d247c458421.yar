rule win_regretlocker_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.regretlocker."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.regretlocker"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8945e0 3bd8 742a 83ec18 8bcc 53 }
		$sequence_1 = { 8d8568ffffff 50 e8???????? 83ec10 c645fc04 8bcc 6a06 }
		$sequence_2 = { e8???????? 6aff 8bcb e8???????? 8d8df4feffff e8???????? 8d8d78ffffff }
		$sequence_3 = { 8d4510 50 8d8578fdffff 50 8d45ec 50 e8???????? }
		$sequence_4 = { 2b45fc 6a18 59 99 f7f9 ff750c 6bc018 }
		$sequence_5 = { 3bf0 59 59 0f95c0 5f 5e }
		$sequence_6 = { 50 f2c3 55 8bec 8b4508 56 }
		$sequence_7 = { 83ec18 8bcc 57 e8???????? e8???????? 83c418 8d4dbc }
		$sequence_8 = { 50 57 ff15???????? 85c0 0f8529ffffff 57 ff15???????? }
		$sequence_9 = { 64890d00000000 5b c9 c21800 8b411c 8b10 85d2 }

	condition:
		7 of them and filesize <1021952
}
