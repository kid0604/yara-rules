import "hash"

rule win_globeimposter_auto_alt_1
{
	meta:
		description = "Detect the risk of Ransomware Globeimposter Rule 3"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 0ff4d0 0f6e6604 0ff4e0 0f6e7608 0ff4f0 0f6e7e0c }
		$sequence_1 = { 45 8364241000 8d442410 50 6880000000 8d44241c }
		$sequence_2 = { 43 85d2 7e18 8d4e7c 8b41fc 3b01 }
		$sequence_3 = { 8b450c 99 33c2 c745f401000000 }
		$sequence_4 = { 48 8bfb 2bf8 89442414 }
		$sequence_5 = { 5e 5b 5f 5d 83c420 c20c00 }
		$sequence_6 = { 7e0e 8d4678 8928 41 8d4014 3b4e6c }
		$sequence_7 = { 7505 6ac4 58 eb2f }
		$sequence_8 = { 8d0445ffffffff 8945f0 8d45fc 8945f8 8d45f0 50 }
		$sequence_9 = { ff15???????? 85c0 7405 3975fc 7405 6afe 58 }

	condition:
		7 of them and filesize <327680
}
