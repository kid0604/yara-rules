rule win_shadowhammer_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.shadowhammer."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shadowhammer"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 03d3 03f3 03fb 894dfc 8945f4 }
		$sequence_1 = { c3 e8???????? c21000 8bff 55 8bec 833d????????01 }
		$sequence_2 = { 8dbd7dfdffff ab ab ab ab }
		$sequence_3 = { 58 6a2d 66894584 58 }
		$sequence_4 = { 685ac1cbc2 56 e8???????? 59 59 85c0 }
		$sequence_5 = { c78564ffffff103ee0fc c78568ffffffb0cf4161 c7856cffffffb0fafb19 8dbd70ffffff }
		$sequence_6 = { 8d45e8 50 ff75fc 895de8 8b07 }
		$sequence_7 = { c78544fdffff6a0ad740 c78548fdffff667aadbd 33c0 8dbd4cfdffff ab 889d50fdffff 8dbd51fdffff }
		$sequence_8 = { 8dbdfcfdffff ab 889d00feffff 8dbd01feffff ab ab }
		$sequence_9 = { 8945a8 8d8574ffffff 33ff 8945ac 8d45b8 }

	condition:
		7 of them and filesize <49152
}
