import "pe"
import "hash"

rule win_revil_auto
{
	meta:
		description = "Detect the risk of Ransomware Sodinokibi Rule 4"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8bb694000000 0fa4da0f c1e911 0bc2 c1e30f 8b5508 0bcb }
		$sequence_1 = { 2345e4 33c7 898bb8000000 8b4de0 8983bc000000 f7d1 }
		$sequence_2 = { 8b9f90000000 8bb788000000 8b978c000000 8945e0 8b477c 8945e4 8b8784000000 }
		$sequence_3 = { 50 51 e8???????? 894608 59 59 85c0 }
		$sequence_4 = { 6802020000 e8???????? 8bf0 59 }
		$sequence_5 = { 55 8bec 83ec10 8d45f0 50 6a0c }
		$sequence_6 = { 897df8 83f803 7cca 8b4508 5f 5e }
		$sequence_7 = { 57 8b7d0c 6685c9 742e 0fb71f 8bd7 6685db }
		$sequence_8 = { 56 57 8b7d08 33f6 397708 7621 8b470c }
		$sequence_9 = { ebca 6b45fc0c 8b4d0c 52 ff540808 59 85c0 }

	condition:
		7 of them and filesize <155794432
}
