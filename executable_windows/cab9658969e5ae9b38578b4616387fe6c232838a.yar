rule win_evilbunny_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.evilbunny."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.evilbunny"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b4dec 8b5104 8b45ec 8b4804 8b12 8bf4 51 }
		$sequence_1 = { eb09 8b450c 8b80b0d91a00 3bf0 7e44 83ee07 eb3f }
		$sequence_2 = { c1e104 8b5508 8b4220 8d4c08f0 8b5508 894a1c 8b4508 }
		$sequence_3 = { 8b4df8 51 e8???????? 83c404 83c028 50 6a00 }
		$sequence_4 = { e8???????? 83c40c 8b55f8 8b4204 50 68???????? 8b4d08 }
		$sequence_5 = { e8???????? 83c40c 837dd808 7308 8b45d8 89458c eb07 }
		$sequence_6 = { c1ea0a 33c2 038558ffffff 8b8d38ffffff c1e907 8b9538ffffff c1e219 }
		$sequence_7 = { e8???????? 034508 50 e8???????? 83c40c 8b45f4 50 }
		$sequence_8 = { c7000b000000 e9???????? 8b4d0c 8b5108 52 6a00 6a05 }
		$sequence_9 = { 8b5598 8b45f8 8902 8b4598 52 8bcd 50 }

	condition:
		7 of them and filesize <1695744
}
