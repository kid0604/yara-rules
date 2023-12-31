rule win_httpsuploader_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.httpsuploader."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.httpsuploader"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 33ff 33d2 41b806020000 6689bc2470020000 e8???????? 488d4c2451 33d2 }
		$sequence_1 = { 33d2 33c9 897c2428 48895c2420 ff15???????? eb3b 488d0dc3bd0000 }
		$sequence_2 = { 4883ec20 488bfa 488bd9 488d0501700000 488981a0000000 83611000 }
		$sequence_3 = { 4c8bc0 418bd4 e8???????? 488d8dd0000000 ff15???????? }
		$sequence_4 = { 488d0d6c280000 4533c9 ba00000040 4489442420 ff15???????? }
		$sequence_5 = { 4c8d25cf7d0000 f0ff09 7511 488b8eb8000000 493bcc }
		$sequence_6 = { 488d0543b50000 eb04 4883c014 4883c428 c3 4053 }
		$sequence_7 = { 488d158e380000 488bc8 ff15???????? 4885c0 0f847a010000 }
		$sequence_8 = { 81fa01010000 7d13 4863ca 8a44191c 4288840170fa0000 }
		$sequence_9 = { 745e 6666660f1f840000000000 488b0d???????? 488d542440 4533c9 4533c0 ff15???????? }

	condition:
		7 of them and filesize <190464
}
