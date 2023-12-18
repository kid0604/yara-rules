rule win_socelars_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.socelars."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.socelars"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { f6462808 894618 7515 8b4c243c ba14000000 e8???????? 89842430010000 }
		$sequence_1 = { 8b4dfc 83b9cc03000020 7409 c745c00c000000 eb07 c745c00e000000 8b55fc }
		$sequence_2 = { ff460c 807e0a00 750a 8bce e8???????? 8a4e09 8b430c }
		$sequence_3 = { ff730c ff7308 e8???????? 8bf8 83c410 85ff 0f8480000000 }
		$sequence_4 = { 8b542410 8b5248 f6421c20 0f8437050000 8b4214 ff4878 8b8888000000 }
		$sequence_5 = { e9???????? 8b4c243c 33c0 89842430010000 ba43000000 8b472c 40 }
		$sequence_6 = { f7da 56 1bd2 83c235 eb55 6a00 ff77c4 }
		$sequence_7 = { e8???????? 83c40c eb36 8d4201 898188000000 8d0c92 8b442438 }
		$sequence_8 = { fe4613 8a4619 fec8 0fb6c8 884619 3bf9 7d24 }
		$sequence_9 = { ff742424 e8???????? 83c40c eb32 8b54241c 8d4101 898688000000 }

	condition:
		7 of them and filesize <2151424
}
