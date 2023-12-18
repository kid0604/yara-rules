rule win_nagini_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.nagini."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nagini"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 0131 1f 0031 1f 003422 0337 }
		$sequence_1 = { a3???????? eb18 6a00 6a00 6a00 6a00 }
		$sequence_2 = { 83c408 85c0 0f8510010000 837c242808 8d442414 68???????? }
		$sequence_3 = { 3422 0536240538 27 06 37 260537260535 230434 }
		$sequence_4 = { 0a06 1408 0412 06 }
		$sequence_5 = { 720e 4e 42 0fb606 80b87081420000 74e9 8b5ddc }
		$sequence_6 = { 668944246c a0???????? 8844246e 8a4701 8d7f01 }
		$sequence_7 = { 6689442444 0f8238020000 ff74242c e8???????? 83c404 e9???????? }
		$sequence_8 = { 0f835ffbffff 03f3 03d3 83fb1f 0f8715040000 ff249da0c64000 }
		$sequence_9 = { b3ac 98 b7b0 9c }

	condition:
		7 of them and filesize <12820480
}
