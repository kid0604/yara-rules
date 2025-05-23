rule win_xiangoop_auto_alt_2
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.xiangoop."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.xiangoop"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b45f4 0fb60c08 81e1ff000000 0bd1 b804000000 }
		$sequence_1 = { 8945ec 837dec00 750e 8b55f8 83c214 8955f8 }
		$sequence_2 = { 81e2ff000000 8b45f8 c1e808 8b75f8 }
		$sequence_3 = { 8b55f0 83c204 8955f0 8b45fc 8b4df0 8b11 8910 }
		$sequence_4 = { 891408 b904000000 6bd103 b804000000 6bc806 8b45fc }
		$sequence_5 = { 8955f8 837df800 7741 7206 837df40a 7339 8b4d08 }
		$sequence_6 = { 8b55fc 330c02 894dec e9???????? 8b45dc }
		$sequence_7 = { c745e408430110 e9???????? 894de0 c745e408430110 e9???????? c745e404430110 e9???????? }
		$sequence_8 = { 6bc203 8b5510 884c020c 8be5 }
		$sequence_9 = { 0bc1 ba01000000 d1e2 8b4df4 0fb6541110 81e2ff000000 c1e208 }

	condition:
		7 of them and filesize <246784
}
