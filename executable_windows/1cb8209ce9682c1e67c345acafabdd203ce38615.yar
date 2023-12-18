rule win_webbytea_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.webbytea."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webbytea"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e9???????? c744242000000000 4533c9 4533c0 33d2 33c9 }
		$sequence_1 = { c68424f100000072 c68424f200000065 c68424f300000061 c68424f400000074 }
		$sequence_2 = { 8b00 ffc0 488b8c2488020000 8901 488d542430 488b4c2420 }
		$sequence_3 = { 488b8c2488020000 8901 488d542430 488b4c2420 ff15???????? 85c0 }
		$sequence_4 = { 488b842488020000 8b00 ffc0 488b8c2488020000 }
		$sequence_5 = { eb08 8b0424 ffc0 890424 8b442438 390424 }
		$sequence_6 = { 488b842488020000 8b00 ffc0 488b8c2488020000 8901 488d542430 488b4c2420 }
		$sequence_7 = { c7042400000000 eb08 8b0424 ffc0 890424 8b442438 }
		$sequence_8 = { 488b8c2488020000 8901 488d542430 488b4c2420 }
		$sequence_9 = { c68424f100000072 c68424f200000065 c68424f300000061 c68424f400000074 c68424f500000065 }

	condition:
		7 of them and filesize <552960
}
