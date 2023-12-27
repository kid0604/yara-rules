rule win_iispy_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.iispy."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.iispy"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ebdc 837b1800 0f85f6000000 3bce 7436 8a01 3c5d }
		$sequence_1 = { d1e8 03d0 8b5e0c 8b7d08 2bd9 03fb }
		$sequence_2 = { 85c0 755e f7459c00100000 7503 8b7608 }
		$sequence_3 = { ff2485887a0010 51 8bcf e8???????? 8b17 8b4210 2b420c }
		$sequence_4 = { 6a00 ff75e4 c745e800000000 ffd6 85c0 0f856effffff eb0c }
		$sequence_5 = { 85f6 0f84c1010000 0fb7460e 8bc8 c1e90a f6c101 }
		$sequence_6 = { 0f1145c8 8b4810 894dc4 b903000000 0f1100 6689480e 8d4dc8 }
		$sequence_7 = { 8955b4 8d0409 50 6a00 52 e8???????? b800100000 }
		$sequence_8 = { f6430801 7411 8d5304 8bcf e8???????? 5f 5e }
		$sequence_9 = { 8b742424 8b7c2420 884c240b 89742410 897c241c e9???????? 3bf8 }

	condition:
		7 of them and filesize <397312
}