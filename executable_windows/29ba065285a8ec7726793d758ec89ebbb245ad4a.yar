rule win_splitloader_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.splitloader."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.splitloader"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 488bc8 ff15???????? 4c8bd8 488905???????? 4885c0 7422 488d151d420000 }
		$sequence_1 = { 48014d00 418b4c241c 418984240cab0000 418b8424f82a0000 894d4c 488b8c2488000000 3bce }
		$sequence_2 = { 4c8d5801 4889442448 4c85d8 0f85ff150000 }
		$sequence_3 = { 488bc8 458d4104 4889742420 ff15???????? 4533c9 }
		$sequence_4 = { e9???????? 8a03 488d1535c30000 ffc7 4a8b0ce2 4188440f4c 4a8b04e2 }
		$sequence_5 = { 895dac 895dbc 895df0 4c894dd0 }
		$sequence_6 = { 0f8c92000000 41838c24042b000001 85c0 0f84ad000000 8b4118 4c8b4910 488b11 }
		$sequence_7 = { 782e 3b0d???????? 7326 4863c9 488d150c930000 488bc1 }
		$sequence_8 = { eb77 4c89ac2400080000 4c8b6808 488b00 39b08c000000 744a 8b9888000000 }
		$sequence_9 = { 4c8d0513700000 41b903000000 488d4c45bc 488bc1 492bc5 48d1f8 }

	condition:
		7 of them and filesize <174080
}
