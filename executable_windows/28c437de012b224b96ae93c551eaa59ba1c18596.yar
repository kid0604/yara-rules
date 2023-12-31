rule win_cradlecore_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.cradlecore."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cradlecore"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 03f2 eb5c 8b45f4 8b0c85f01f4300 f644190448 7437 }
		$sequence_1 = { 720f 8b06 5f c60000 8bc6 }
		$sequence_2 = { 83e908 8d7608 660fd60f 8d7f08 8b048db8734000 ffe0 f7c703000000 }
		$sequence_3 = { e8???????? 51 51 53 8bd9 33c0 8945f0 }
		$sequence_4 = { e8???????? 83c410 3bc3 75cf 0fb644240f e9???????? c74424340f000000 }
		$sequence_5 = { 80fb5a 7e53 80fb2d 744e 80fb2e }
		$sequence_6 = { 8b5df4 8b7df0 33f6 8bce 8b75fc }
		$sequence_7 = { 7204 8b1e eb02 8bde 8b450c 33d2 8b4d08 }
		$sequence_8 = { 59 50 8d45d0 8bce 50 e8???????? 837da010 }
		$sequence_9 = { 53 50 68???????? 53 ff15???????? 8d4de8 c745e868747470 }

	condition:
		7 of them and filesize <450560
}
