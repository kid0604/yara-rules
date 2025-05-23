rule win_7ev3n_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.7ev3n."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.7ev3n"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 75f5 2bf9 d1ff 6a00 8d8558fdffff }
		$sequence_1 = { b8ffff0000 0fb7c0 0fb7c0 0fb7f0 eb52 }
		$sequence_2 = { 660fd68518e1ffff 0fb705???????? 66898520e1ffff f30f7e05???????? 660fd6850ce1ffff 0fb705???????? }
		$sequence_3 = { 8bd0 8bf0 668b02 83c202 6685c0 75f5 8dbd38f9ffff }
		$sequence_4 = { 660fd6850cf9ffff 0fb705???????? 66898514f9ffff f30f7e05???????? 660fd68500f9ffff 0fb705???????? 66898508f9ffff }
		$sequence_5 = { 6a00 8d858ce8ffff 50 8d8dd0cdffff e8???????? 8bce 2bcf }
		$sequence_6 = { d1ff 6a00 8d85e8f2ffff 50 8d8dd0cdffff e8???????? 8bce }
		$sequence_7 = { 0f4305???????? a3???????? c3 b9???????? e8???????? 68???????? e8???????? }
		$sequence_8 = { 85ff 7f17 7c05 83fe01 7710 0f57c0 660f1345e0 }
		$sequence_9 = { 83c702 6685c0 75f5 2bf9 d1ff 6a00 8d85d8e1ffff }

	condition:
		7 of them and filesize <803840
}
