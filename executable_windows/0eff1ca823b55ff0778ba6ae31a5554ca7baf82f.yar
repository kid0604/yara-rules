rule win_ncctrojan_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.ncctrojan."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ncctrojan"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7536 8b85e8feffff 85c0 750a 68???????? }
		$sequence_1 = { 68???????? e9???????? 83f801 750a }
		$sequence_2 = { 83f801 750a 68???????? e9???????? 83f802 }
		$sequence_3 = { 68e9fd0000 ffd6 8d8decfdffff 5f 8d5102 5e 668b01 }
		$sequence_4 = { 8b442420 83c40c 83c008 836c240c01 89442414 0f85fffdffff }
		$sequence_5 = { 8d4a10 0f1f840000000000 0f1041f0 83c020 }
		$sequence_6 = { ffd6 50 8d85dcfdffff 50 }
		$sequence_7 = { e8???????? 83c40c 85c0 752f 6a06 8d85c4bfffff }
		$sequence_8 = { 51 f2c3 8b4df0 33cd f2e8bef6ffff }
		$sequence_9 = { 83c414 e8???????? 84c0 7517 }
		$sequence_10 = { 33c5 8945fc 56 6890010000 }
		$sequence_11 = { 83faff 0f94c0 84c0 7405 }
		$sequence_12 = { 83c418 83c008 03c6 8bcf }
		$sequence_13 = { 0fb601 50 8d45d0 68???????? 50 }
		$sequence_14 = { 83ec14 c645fc1f 8d95e8feffff 8bcc }
		$sequence_15 = { 668bc1 8be5 5d c3 56 8bf1 }

	condition:
		7 of them and filesize <1160192
}