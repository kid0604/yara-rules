rule win_newposthings_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.newposthings."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.newposthings"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c78534feffff00000000 c68524feffff00 c645fc00 83bd54feffff10 720e ffb540feffff e8???????? }
		$sequence_1 = { ff75d4 e8???????? 8bf8 83c404 85ff 7528 50 }
		$sequence_2 = { 6a02 c78578ffffff00000000 c7857cffffff00000000 68e0c40110 8d8d68ffffff }
		$sequence_3 = { c741140f000000 c7411000000000 50 c60100 e8???????? c645fc02 83ec18 }
		$sequence_4 = { 83c408 85ff 7531 ffb5f4fcffff 68e8030000 56 e8???????? }
		$sequence_5 = { 833d????????10 722e 56 8b35???????? 8d4dff e8???????? 6848110210 }
		$sequence_6 = { 64a300000000 8bf1 8975f0 c745fc01000000 8d4e04 c741140f000000 c7411000000000 }
		$sequence_7 = { 83fe14 7250 83ec18 8bcc 89658c 6aff }
		$sequence_8 = { 8d842480010000 64a300000000 8bf9 68c8200210 ff15???????? 6804010000 8d442470 }
		$sequence_9 = { c78500ffffff00000000 c685f0feffff00 c645fc15 83bdb8feffff10 720e ffb5a4feffff }

	condition:
		7 of them and filesize <827392
}
