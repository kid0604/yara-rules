rule win_ceeloader_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.ceeloader."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ceeloader"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83c8ff f00fc101 83f801 751c 488b45e8 488b8888000000 488d05f5cf0800 }
		$sequence_1 = { 89842488040000 8b84245c0c0000 0b8424600c0000 8984245c0c0000 8b8424600c0000 0b8424600c0000 898424600c0000 }
		$sequence_2 = { 448b942444020000 4531d0 c78424b40d000000000000 488b9424d8070000 48898c2438020000 4889d1 488d1521160b00 }
		$sequence_3 = { 44899c2454040000 448b9c2454040000 89c6 81e6b1524402 89b42450040000 8bb42450040000 c1e604 }
		$sequence_4 = { 4181e100ffffff 44898c24fc000000 448b8c24fc000000 448b15???????? 4501c8 4539d0 48898424b0000000 }
		$sequence_5 = { 0f8433000000 8b842418010000 898424d0000000 e8???????? 8b8c2414010000 2b8c2418010000 99 }
		$sequence_6 = { 4c8d0d7d050e00 488b8c2410010000 4889942400010000 4c89ca 4c8b8c2400010000 898424fc000000 ff15???????? }
		$sequence_7 = { 6689d3 66239c2476110000 66899c2474110000 6689d3 66239c2474110000 66899c2472110000 6689d3 }
		$sequence_8 = { 4181e1f5274b02 44898c24d0050000 448b8c24d0050000 4189c2 4181e2f5274b02 44899424cc050000 448b9424cc050000 }
		$sequence_9 = { 0315???????? 8915???????? 8b15???????? 448b05???????? 4189d2 4531c2 4431d2 }

	condition:
		7 of them and filesize <2321408
}
