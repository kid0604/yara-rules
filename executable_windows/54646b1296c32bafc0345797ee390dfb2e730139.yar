rule win_mebromi_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.mebromi."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mebromi"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 743a 837d0800 742e 85f6 7419 0fb6da f68301a0290004 }
		$sequence_1 = { 68ff010f00 68???????? ff742410 ff15???????? 8bf0 85f6 7416 }
		$sequence_2 = { 7714 8b55fc 8a9270722900 089001a02900 }
		$sequence_3 = { 683f000f00 55 55 ff15???????? 8bf0 e8???????? 56 }
		$sequence_4 = { 48 750c e8???????? eb05 e8???????? 6a01 }
		$sequence_5 = { 0fb6fa 3bc7 7714 8b55fc 8a9270722900 089001a02900 }
		$sequence_6 = { 2c29 0000 2d29008a46 0323 d18847034ec1 e9???????? }
		$sequence_7 = { 0fb6d2 f68201a0290004 740c ff01 }
		$sequence_8 = { aa 8d9e88722900 803b00 8bcb 742c 8a5101 84d2 }
		$sequence_9 = { 50 6a01 56 ff15???????? 56 8bf8 ff15???????? }

	condition:
		7 of them and filesize <106496
}