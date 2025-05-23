rule win_unidentified_077_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.unidentified_077."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_077"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 410fb74716 c1e80d 83e001 48896e58 894620 488d058dfcffff 48894628 }
		$sequence_1 = { ba30750000 c744242030750000 448bca 448bc2 488bcf ff15???????? }
		$sequence_2 = { 48895c2458 ff15???????? 488bf8 4885c0 750e ff15???????? }
		$sequence_3 = { 2bcb 3bc8 7653 8bd1 }
		$sequence_4 = { 4883ec38 33c0 4c8d05b3feffff 4889442428 4533c9 }
		$sequence_5 = { ff15???????? 488bce 418907 ff15???????? }
		$sequence_6 = { 83e03f 2bc8 48d3cf 4933fa 4b87bcf7e0c70100 33c0 }
		$sequence_7 = { 83e001 48896e58 894620 488d058dfcffff 48894628 488d0592fcffff }
		$sequence_8 = { e9???????? 493bec 0f84be000000 8b7500 33c0 f04d0fb1bcf180bf0100 }
		$sequence_9 = { 8bc2 f30f6f0418 660fefc1 f30f7f0418 8d4210 }

	condition:
		7 of them and filesize <270336
}
