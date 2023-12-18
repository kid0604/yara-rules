rule win_sagerunex_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.sagerunex."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sagerunex"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 4c8bb424d8010000 c744245001000000 4c896c2458 4c896c2460 4885c9 742c 4a8d04fd00000000 }
		$sequence_1 = { 72d1 498bd4 483bd7 488d4de7 480f42fa 488bd7 e8???????? }
		$sequence_2 = { c74324a44ffabe 488bcb 89b3e8000000 c70340000000 e8???????? 488d442420 c60000 }
		$sequence_3 = { 498bcc e8???????? 85c0 7849 488d45b0 488d55f0 498bcf }
		$sequence_4 = { e8???????? e8???????? ffc7 448bc0 b84fecc44e 41f7e8 c1fa03 }
		$sequence_5 = { 4d894838 4c8b5340 458bca 4983d300 49c1ea20 418bc9 4d0fafcf }
		$sequence_6 = { 894260 33d2 e8???????? 488d442470 488d15d0230300 }
		$sequence_7 = { 83f803 7cc5 eb04 897c2450 443bfe 752a 448b7c2444 }
		$sequence_8 = { 498bcf c745df02000000 c745fb01000000 c745e301000000 ff15???????? 85c0 7507 }
		$sequence_9 = { 4403c0 418bc6 4503c2 c1c007 c1ca0b 33d0 418bc6 }

	condition:
		7 of them and filesize <619520
}
