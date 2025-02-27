rule win_systembc_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.systembc."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.systembc"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8bec 53 57 56 8b7d10 }
		$sequence_1 = { 7507 66837fff00 740d 837d1000 7409 66837aff00 7502 }
		$sequence_2 = { 8b4d0c 837d0c00 750b ff7508 e8???????? }
		$sequence_3 = { 837d0cfe 751c 837d1000 7507 66837fff00 }
		$sequence_4 = { 50 8b45f8 8b08 50 8b4178 }
		$sequence_5 = { 6a00 8d85fcfbffff 50 8b45f8 8b08 }
		$sequence_6 = { 740d 837d1000 7409 66837aff00 7502 eb2e }
		$sequence_7 = { 837d0cfe 751c 837d1000 7507 66837fff00 740d 837d1000 }
		$sequence_8 = { c9 c21400 55 8bec 53 57 56 }
		$sequence_9 = { 8b450c ab 8b4514 ab }

	condition:
		7 of them and filesize <75776
}
