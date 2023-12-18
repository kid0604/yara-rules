rule win_sodamaster_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.sodamaster."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sodamaster"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? c70009000000 e8???????? ebd2 8bc3 c1f805 8d3c85a0330110 }
		$sequence_1 = { 8908 894804 8bf0 eb02 33f6 6a40 6800100000 }
		$sequence_2 = { 8d4900 8d97feefff7f 85d2 7419 8a140e 84d2 7412 }
		$sequence_3 = { 8945e4 3d01010000 7d0d 8a4c181c 888810080110 40 }
		$sequence_4 = { 33f6 6a40 6800100000 8d4301 50 6a00 ff15???????? }
		$sequence_5 = { 83c424 83ffff 5f 5e 5b }
		$sequence_6 = { 83c8ff e9???????? 8bc6 c1f805 8bfe 53 8d1c85a0330110 }
		$sequence_7 = { 33f6 8d45f8 50 8b4508 c745e8636d643d c645ec00 }
		$sequence_8 = { e8???????? 56 e8???????? 83c418 ff15???????? }
		$sequence_9 = { 6a02 53 68ff010f00 52 }

	condition:
		7 of them and filesize <134144
}
