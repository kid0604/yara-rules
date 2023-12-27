rule win_cova_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.cova."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cova"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b430c 8905???????? 8bd7 4c8d0558bbffff }
		$sequence_1 = { eb7c 4c8d258e800000 488b0d???????? eb6c }
		$sequence_2 = { 4881c354020000 83fe06 7298 488d8d70040000 baf80d0000 }
		$sequence_3 = { 3d80000000 751d 4c8be6 448bfe 4839742450 7419 ff5500 }
		$sequence_4 = { 4863ca 0fb7444b10 664189844898c90000 ffc2 }
		$sequence_5 = { 488b0d???????? e9???????? 4c8d25a6800000 488b0d???????? }
		$sequence_6 = { eb06 8d4257 418800 ffc2 49ffc0 83fa10 }
		$sequence_7 = { e8???????? 482be0 488b05???????? 4833c4 48898510170000 488dbde0000000 }
		$sequence_8 = { ff15???????? 488d1574260000 488bce 488905???????? ff15???????? }
		$sequence_9 = { 41bc14030000 4c8d0520320000 488bcd 418bd4 }

	condition:
		7 of them and filesize <123904
}