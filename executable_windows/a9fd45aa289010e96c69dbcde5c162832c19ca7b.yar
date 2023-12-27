rule win_applejeus_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.applejeus."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.applejeus"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8902 8b4608 8b08 8b4604 810044f3ffff 8100bc0c0000 }
		$sequence_1 = { 8b4604 8b00 33c2 0f8583000000 c745f45b000000 8b45f4 83f032 }
		$sequence_2 = { 8945dc 8d45d0 c745d0a08e4200 897dd4 8975d8 0f1145b0 }
		$sequence_3 = { 8b4a04 50 0f1145c8 c745a8e0294200 0f1145d8 897dac 8975b0 }
		$sequence_4 = { e8???????? 8b4dc8 83c414 8945cc 89851cffffff c700???????? 897004 }
		$sequence_5 = { c745e400000000 8b410c 50 6a00 51 8b04851cfb4600 ffd0 }
		$sequence_6 = { c68589f5ffff7d c6858af5ffff85 c6858bf5ffff72 c6858cf5ffff83 c6858df5ffff59 c6858ef5ffff3a c6858ff5ffff77 }
		$sequence_7 = { 8d4db0 e9???????? 8d4db4 e9???????? 8d4dac e9???????? 8b542408 }
		$sequence_8 = { e8???????? 8b7588 8d4d94 83c418 e8???????? c78568ffffffd5030000 8b8568ffffff }
		$sequence_9 = { 8d85d42e0000 50 ff15???????? 57 ff15???????? e9???????? ff15???????? }

	condition:
		7 of them and filesize <1245184
}