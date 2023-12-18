rule win_ehdevel_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.ehdevel."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ehdevel"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 51 e8???????? e9???????? 33d2 68fe070000 52 8d85feefffff }
		$sequence_1 = { 7545 56 c70303000000 ff15???????? 56 ff15???????? 68???????? }
		$sequence_2 = { 8d8dcce7ffff 51 6a00 6813000020 56 c785cce7ffff00000000 c785c8e7ffff04000000 }
		$sequence_3 = { 8d85f0e7ffff 50 56 6a00 6a10 6a02 ff15???????? }
		$sequence_4 = { e8???????? 83c404 33c9 6a08 b8???????? }
		$sequence_5 = { 8d8dd4e5ffff 51 8d95f8f7ffff 6800040000 52 e8???????? }
		$sequence_6 = { 83c410 8b4d0c 8d442408 50 51 }
		$sequence_7 = { 83d8ff 85c0 0f84cffdffff 68???????? 6800040000 57 e8???????? }
		$sequence_8 = { 50 e8???????? 8d8c24d4190000 51 8d9424d8010000 6800040000 52 }
		$sequence_9 = { 8db564f7ffff e8???????? 33d2 899de8f7ffff 89bde4f7ffff 668995d4f7ffff 33c0 }

	condition:
		7 of them and filesize <524288
}
