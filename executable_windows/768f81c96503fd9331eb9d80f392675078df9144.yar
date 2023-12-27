rule win_mongall_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.mongall."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mongall"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 8b400c 8b08 8b11 52 ff15???????? ba???????? }
		$sequence_1 = { 85ff 747c 56 57 68???????? e8???????? 68???????? }
		$sequence_2 = { f3a5 8bc8 8b8500d9ffff 83e103 43 }
		$sequence_3 = { 59 8985a0fdffff 3bc1 0f87cb090000 ff2485e6574000 838de8fdffffff 89b594fdffff }
		$sequence_4 = { 8bd8 83fbff 7448 68???????? e8???????? }
		$sequence_5 = { e8???????? 8bfc 85ff 741d 8b8df4fdffff 56 }
		$sequence_6 = { 56 8d45f0 33f6 50 8935???????? 8935???????? ff15???????? }
		$sequence_7 = { 8b7df0 8bc7 5f 5e c60300 }
		$sequence_8 = { 89b5e4fdffff 89b5e0fdffff 89b5c0fdffff 888deffdffff }
		$sequence_9 = { 85f6 5e 741d 8d85f8feffff }

	condition:
		7 of them and filesize <199680
}