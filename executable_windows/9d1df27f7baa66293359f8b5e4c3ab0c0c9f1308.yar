rule win_cueisfry_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.cueisfry."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cueisfry"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? b8???????? c3 8b45ec c745fcffffffff 85c0 7406 }
		$sequence_1 = { f3a5 52 e8???????? 8d44241c }
		$sequence_2 = { e8???????? 85c0 750c 55 ff15???????? e9???????? }
		$sequence_3 = { 8944241c 7c0d 80f95a 7f08 0fbee9 }
		$sequence_4 = { 8975dc e8???????? 8b45ec 3bc7 750d }
		$sequence_5 = { 8d4c2408 50 e8???????? b91f000000 33c0 8d7c2431 c644243000 }
		$sequence_6 = { ff15???????? 8bb424a8010000 8d4c240c 51 8bce }
		$sequence_7 = { 5f 5e 5d 32c0 5b 81c424030000 c3 }
		$sequence_8 = { 8d4c240c c68424a001000001 e8???????? 8d8c24ac010000 889c24a0010000 e8???????? }
		$sequence_9 = { 6a00 ff15???????? 68d0070000 ff15???????? 8d94249c000000 6a00 }

	condition:
		7 of them and filesize <81920
}
