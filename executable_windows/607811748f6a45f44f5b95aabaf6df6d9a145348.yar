rule win_bs2005_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.bs2005."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bs2005"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 85c0 0f845f030000 8b500c }
		$sequence_1 = { 7505 b83f000000 8d5abf 83c9ff 80fb19 771c 0fbeca }
		$sequence_2 = { 51 50 8b02 83c041 50 e8???????? 8b974c060000 }
		$sequence_3 = { 8b02 8a9049000400 8b8f54060000 889111010000 }
		$sequence_4 = { 51 c645c800 e8???????? 83c40c b9???????? 8d8324010000 8da42400000000 }
		$sequence_5 = { eb09 3c2f 7505 b93f000000 8d5abf 83c8ff 80fb19 }
		$sequence_6 = { 50 8d9500ffffff 52 68???????? e8???????? 6804010000 6a00 }
		$sequence_7 = { ffd6 33c0 68???????? 8d4dec 68???????? 51 8945ec }
		$sequence_8 = { 8945f8 3b45f0 7cea 8b4510 }
		$sequence_9 = { 8d419f 3c19 7708 0fbef1 83ee47 eb25 }

	condition:
		7 of them and filesize <212992
}
