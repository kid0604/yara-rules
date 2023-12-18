rule win_himan_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.himan."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.himan"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b7b04 33ee 8b7068 0554010000 c1e204 33f7 }
		$sequence_1 = { 8b442410 3bd0 7422 56 ff15???????? 57 ff15???????? }
		$sequence_2 = { 894c2414 8bcb c1e910 81e1ff000000 }
		$sequence_3 = { c1e008 0bc7 c1e008 0bc1 8bc8 8904b594886e00 }
		$sequence_4 = { 8bda c1eb18 8b2cad948c6e00 332c9d94946e00 8bd9 c1eb10 81e3ff000000 }
		$sequence_5 = { 8b08 50 ff5108 8b8c24a8050000 5f }
		$sequence_6 = { 8d85a0fcffff 50 ff15???????? 8da594d4ffff 5f 5e 5b }
		$sequence_7 = { c1e910 3334adbcc26e00 8beb 81e5ff000000 81e1ff000000 c1eb08 3334adbcba6e00 }
		$sequence_8 = { 333c9594946e00 8b542414 c1ea10 81e2ff000000 333c9594906e00 8bd1 81e2ff000000 }
		$sequence_9 = { c1c108 890cb5948c6e00 8a8ebccb6e00 8bd0 884c2410 8b7c2410 c1c210 }

	condition:
		7 of them and filesize <139264
}
