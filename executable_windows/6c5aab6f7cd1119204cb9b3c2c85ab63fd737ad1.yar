rule win_xsplus_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.xsplus."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xsplus"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b4608 8b7e20 8b36 66394f18 75f2 }
		$sequence_1 = { 51 6801000080 ff15???????? 85c0 7529 8b5518 52 }
		$sequence_2 = { 6a40 0020 6b40008a 46 }
		$sequence_3 = { 8b8da4feffff 51 6a00 ff15???????? }
		$sequence_4 = { 52 ff15???????? 6a2e 8d85f8feffff 50 }
		$sequence_5 = { a1???????? c705????????04264000 8935???????? a3???????? ff15???????? a3???????? 83f8ff }
		$sequence_6 = { 837dc400 7505 8b45e0 eb63 }
		$sequence_7 = { 7453 83bdb8fdffff10 7436 e9???????? 81bdb8fdffff11010000 }
		$sequence_8 = { 8945dc 6a05 8b45dc 50 }
		$sequence_9 = { e9???????? 8975e4 33c0 39b810a84000 0f8491000000 }
		$sequence_10 = { a1???????? a3???????? a1???????? c705????????04264000 8935???????? }
		$sequence_11 = { ff75e4 ffd3 8986fc010000 897e70 c686c800000043 c6864b01000043 c74668e0a34000 }
		$sequence_12 = { 3945e0 7608 8b45e0 e9???????? c685f8feffff00 b918000000 33c0 }
		$sequence_13 = { 8bec 83ec2c c745d406000000 6a00 6a00 6809100000 }
		$sequence_14 = { 51 8b55fc 8b02 8b4dfc 51 ff500c }
		$sequence_15 = { ff15???????? 83c40c 8d95fcfeffff 52 ff15???????? 6a00 6880000000 }
		$sequence_16 = { 8b8d90feffff 51 e8???????? 83c404 b801000000 eb02 }

	condition:
		7 of them and filesize <597872
}
