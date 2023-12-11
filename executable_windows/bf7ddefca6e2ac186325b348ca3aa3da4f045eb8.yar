rule win_oddjob_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.oddjob."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.oddjob"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 85c0 0f857afdffff 8b958494ffff 56 8d4d9c e8???????? }
		$sequence_1 = { 889d68f9ffff 889d69f9ffff c6856af9ffff66 c6856bf9ffff81 c6856cf9ffff7b }
		$sequence_2 = { c6858af8ffff6f c6858bf8ffffe8 c6858cf8ffff5e c6858df8ffff05 889d8ef8ffff 889d8ff8ffff }
		$sequence_3 = { 898dbcf7ffff 899dc8f7ffff c685d0f7ffff60 c685d1f7ffff6a }
		$sequence_4 = { 8845b4 8845ba 8845d4 8845da 8845df 8845fa 8845fb }
		$sequence_5 = { 7cec 8d442418 50 ff7510 ff750c 6a10 58 }
		$sequence_6 = { 85c0 751e 8b45f8 8b08 57 53 }
		$sequence_7 = { c645ab51 c645ac6a c645ad04 8845ae c645afb3 c645b082 885db1 }
		$sequence_8 = { 7522 33c0 40 3985f0feffff 740b 83bdf0feffff00 7402 }
		$sequence_9 = { 83c304 899de8fbffff 8b5bfc 85db }

	condition:
		7 of them and filesize <221184
}
