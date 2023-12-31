rule win_ddkeylogger_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.ddkeylogger."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ddkeylogger"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8bf7 83e61f c1e606 03348580ee4500 }
		$sequence_1 = { 51 894df4 8955fc 8945f8 e8???????? 83c408 }
		$sequence_2 = { 8bc8 c1e902 f3a5 8bc8 8d95e8faffff 83e103 52 }
		$sequence_3 = { 0fb64f08 80cbff d2e3 40 f6d3 205c30ff 0fb64f08 }
		$sequence_4 = { 0405 c3 f6c20c 7409 f6c208 0f95c0 }
		$sequence_5 = { 52 50 8b81e0000000 ffd0 837df804 75e8 }
		$sequence_6 = { c745fc00000000 e8???????? 83c40c 8d85ccfaffff 50 8d8df0fdffff 51 }
		$sequence_7 = { 50 57 ffd3 8945bc 8d45c8 50 }
		$sequence_8 = { ff248d4cf74000 8d48cf 80f908 7706 6a03 }
		$sequence_9 = { 6bc930 8975e0 8db1c0624100 8975e4 }

	condition:
		7 of them and filesize <808960
}
