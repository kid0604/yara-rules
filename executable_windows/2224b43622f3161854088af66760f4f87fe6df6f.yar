rule win_ratel_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.ratel."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ratel"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 89d9 e8???????? 85c0 75e7 89d9 e8???????? 89d9 }
		$sequence_1 = { a1???????? 85c0 0f85bb010000 8b41fc 8d50ff 8951fc }
		$sequence_2 = { 8b442454 8b542414 8b400c 85d2 0f851f040000 83f802 }
		$sequence_3 = { 8bbc24b0000000 e8???????? 8b00 c744245cffffffff c7442460ffffffff 89442428 8b8424a4000000 }
		$sequence_4 = { 0f83a3020000 0fb700 6683f8ff b800000000 0f4545ac 8945ac b800000000 }
		$sequence_5 = { 668993f0000000 c783f400000000000000 c783f800000000000000 c783fc00000000000000 c7830001000000000000 c703???????? c7437c98ce4b00 }
		$sequence_6 = { c703???????? c7437884124c00 e8???????? 89b3f0000000 83ec04 8d65f4 5b }
		$sequence_7 = { 0f9fc1 084dc9 8b4d08 8345cc01 8b4108 3b410c 0f8240ffffff }
		$sequence_8 = { 8b4340 c7431400000000 c7431000000000 0fb67b58 894304 894308 89430c }
		$sequence_9 = { 8d4304 89c1 89c6 e8???????? 89b3ec000000 83ec04 8d65f4 }

	condition:
		7 of them and filesize <2174976
}
