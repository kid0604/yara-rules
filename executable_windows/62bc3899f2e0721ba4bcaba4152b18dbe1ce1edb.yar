rule win_blackbyte_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.blackbyte."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.blackbyte"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 488d15bc010000 4889542478 4889842480000000 488d542478 4889942490000000 c644242701 }
		$sequence_1 = { 488d0db4020000 488908 833d????????00 7520 488b4c2428 48894808 }
		$sequence_2 = { 0fb64210 88442408 0fb64211 88442409 }
		$sequence_3 = { 0fb6420b 8844240b 0fb6420c 8844240c 0fb6420d 8844240d 0fb6420e }
		$sequence_4 = { 488d4a01 488b442428 488b5c2430 4883f903 }
		$sequence_5 = { 0101 ffc5 3b6b68 0f82e6feffff }
		$sequence_6 = { 488d542478 4889942490000000 c644242701 488b9c24a8000000 488b8c24b0000000 e8???????? }
		$sequence_7 = { 488d4250 488b542430 488d5a50 b918000000 }
		$sequence_8 = { 0fb6420d 8844240d 0fb6420e 8844240e 0fb6420f 8844240f }
		$sequence_9 = { 488d542470 4889942488000000 c644241f01 488b9c24a0000000 }
		$sequence_10 = { 488d4a01 488b442430 488b5c2438 90 4883f90f }
		$sequence_11 = { 0fb64212 8844240a 0fb64213 8844240b }
		$sequence_12 = { 0fb6420f 8844240f 488b442408 48894108 }
		$sequence_13 = { 488d5c244b b902000000 0f1f440000 e8???????? }
		$sequence_14 = { 014608 498bce ffd7 448b85e8040000 }
		$sequence_15 = { 0fb64211 88442409 0fb64212 8844240a }

	condition:
		7 of them and filesize <9435136
}
