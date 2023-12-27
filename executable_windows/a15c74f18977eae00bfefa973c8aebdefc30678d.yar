rule win_chewbacca_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.chewbacca."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chewbacca"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? c645f401 8a45f4 5b c9 }
		$sequence_1 = { e8???????? c645c800 8b45cc 8b10 }
		$sequence_2 = { e8???????? c645f000 8b45f4 8b80b4010000 }
		$sequence_3 = { e8???????? c645a400 c645f400 806df401 }
		$sequence_4 = { e8???????? c645d001 8a45d0 5f }
		$sequence_5 = { e8???????? c645ec01 e9???????? 8b55dc }
		$sequence_6 = { e8???????? c645f401 e8???????? 8d4590 e8???????? 58 }
		$sequence_7 = { e8???????? c645a400 6a00 8b45f8 8b00 898554ffffff }

	condition:
		7 of them and filesize <9764864
}