rule win_pandabanker_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.pandabanker."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pandabanker"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 56 8bf2 57 83f8ff 7507 8bce e8???????? }
		$sequence_1 = { 57 8b4808 8d7c2418 8b4004 }
		$sequence_2 = { c1e202 8bfe 8bca 45 }
		$sequence_3 = { 7404 c6400109 8b442430 8bd5 014608 8bcf 56 }
		$sequence_4 = { eb2c 6a05 5a 8bcf }
		$sequence_5 = { c6007b 40 85db 7404 c6000a 40 c60000 }
		$sequence_6 = { e8???????? 8bf0 85f6 7411 8bcf }
		$sequence_7 = { 85ff 7423 8b0e 8bd5 }
		$sequence_8 = { e8???????? 8b742414 8bce 8b542418 89742424 e8???????? 84c0 }
		$sequence_9 = { 7508 33c0 85d2 0f95c0 c3 }

	condition:
		7 of them and filesize <417792
}
