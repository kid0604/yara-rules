rule win_revil_auto_alt_2
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.revil."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.revil"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 334f1c 83c720 d1f8 83e801 89450c e9???????? 8b7510 }
		$sequence_1 = { 50 e8???????? 8b7d08 8db568ffffff 83c414 }
		$sequence_2 = { 83e801 eb07 b00a 5d c3 83e862 7428 }
		$sequence_3 = { 8d8510ffffff 50 8d8560ffffff 50 8d45b0 50 e8???????? }
		$sequence_4 = { ff750c 8d45b0 50 8d85c0feffff 50 }
		$sequence_5 = { 8b4508 8b404c 8945f0 8b45e8 894b28 f7d0 23c2 }
		$sequence_6 = { 334de0 8b4048 8b5d08 8945ec 8b4508 }
		$sequence_7 = { ff7520 e8???????? 8d8580feffff 50 ff7524 }
		$sequence_8 = { 8975d8 0fb645ff 0bc8 8bc1 894dd8 }
		$sequence_9 = { 83e813 0f8461060000 83e83d 0f84fa020000 f6c204 7411 80f92c }

	condition:
		7 of them and filesize <155794432
}
