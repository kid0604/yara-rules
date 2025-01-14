rule win_zebrocy_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.zebrocy."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zebrocy"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8945e4 e8???????? 89f9 89c6 e8???????? 8b55e4 }
		$sequence_1 = { 8d45f4 64a300000000 8b01 8d7160 8b4804 8975f0 c74431a05c444200 }
		$sequence_2 = { ff0d???????? ff15???????? 8b0d???????? 89048d489b4200 }
		$sequence_3 = { 8bc8 8bc6 c644246001 e8???????? be10000000 3974242c 720d }
		$sequence_4 = { a3???????? 8078086c 7507 c605????????01 }
		$sequence_5 = { 8d51bf 55 8d4120 80fa19 89e5 }
		$sequence_6 = { c686c800000043 c6864b01000043 c74668d0874200 6a0d }
		$sequence_7 = { 83f83f 7f07 894c8204 40 8902 5d }
		$sequence_8 = { 53 8d70ff 31db 31c0 39f3 }
		$sequence_9 = { 7505 e8???????? 84db 7407 }
		$sequence_10 = { b9ffff0000 663bc8 750e c745ec04000000 8da42400000000 837dec00 }
		$sequence_11 = { 8b4508 33f6 89b578ffffff ba0f000000 895314 }
		$sequence_12 = { 42 89f9 884b08 ebe7 83c42c 5b }
		$sequence_13 = { e9???????? 8d4dd4 e9???????? 8d8d08ffffff e9???????? 8d4db8 }
		$sequence_14 = { 7306 8d8508f7ffff 8a1c38 8db598f6ffff e8???????? }
		$sequence_15 = { eb50 31d2 89d9 e8???????? }

	condition:
		7 of them and filesize <393216
}
