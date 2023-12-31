rule win_lilith_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.lilith."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.lilith"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 50 ff15???????? 6857040000 898698210000 ff15???????? }
		$sequence_1 = { e8???????? 8bce e8???????? 83c418 8bcf e8???????? 8d4dd0 }
		$sequence_2 = { 8b0c85a84b4300 8b45e8 f644012880 7446 0fbec3 83e800 742e }
		$sequence_3 = { 25f0070000 660f28a010e94200 660f28b800e54200 660f54f0 660f5cc6 660f59f4 660f5cf2 }
		$sequence_4 = { 8b0485a84b4300 80640828fe ff33 e8???????? 59 e9???????? 8b0b }
		$sequence_5 = { c60000 833d????????10 b8???????? c745cc01000000 0f4305???????? }
		$sequence_6 = { e9???????? c745dc03000000 c745e0c8874200 e9???????? }
		$sequence_7 = { c1fa06 8934b8 8bc7 83e03f 6bc830 8b0495a84b4300 8b440818 }
		$sequence_8 = { 8b4d08 898814434300 68???????? e8???????? 8be5 }
		$sequence_9 = { 660f122c8510a74200 03c0 660f28348520ab4200 ba7f3e0400 e9???????? 8bd0 }

	condition:
		7 of them and filesize <499712
}
