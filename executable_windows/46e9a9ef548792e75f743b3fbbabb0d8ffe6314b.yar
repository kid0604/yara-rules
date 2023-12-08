rule win_badencript_auto
{
	meta:
		description = "Detect the risk of Ransomware BadEncript Rule 2"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8bc1 83e13f c1f806 6bc930 8b048548414100 0fb6440828 }
		$sequence_1 = { 8d7f08 8b048d04b54000 ffe0 f7c703000000 7413 8a06 8807 }
		$sequence_2 = { 83c8ff eb07 8b04cdecfd4000 5f 5e 5b 8be5 }
		$sequence_3 = { 83e03f c1f906 6bc030 03048d48414100 }
		$sequence_4 = { 8b049548414100 804c182d04 ff4604 eb08 ff15???????? }
		$sequence_5 = { 8b1c9d68d14000 56 6800080000 6a00 53 ff15???????? 8bf0 }
		$sequence_6 = { 6a00 6a03 6a00 6a04 6800000010 }
		$sequence_7 = { 33c0 3b0cc520db4000 7427 40 83f82d 72f1 }
		$sequence_8 = { c1fa06 8bc6 83e03f 6bc830 8b049548414100 f644082801 }
		$sequence_9 = { 8bc8 d1f9 6a41 5f 894df0 8b34cde8fd4000 }

	condition:
		7 of them and filesize <335872
}
