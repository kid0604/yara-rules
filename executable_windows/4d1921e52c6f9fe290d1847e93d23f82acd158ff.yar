rule PrikormkaDropper_alt_1
{
	meta:
		description = "Detects PrikormkaDropper_alt_1 dropper malware"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4D 5A }
		$kd1 = "KDSTORAGE" wide
		$kd2 = "KDSTORAGE_64" wide
		$kd3 = "KDRUNDRV32" wide
		$kd4 = "KDRAR" wide
		$bin1 = {69 65 04 15 00 14 1E 4A 16 42 08 6C 21 61 24 0F}
		$bin2 = {76 6F 05 04 16 1B 0D 5E 0D 42 08 6C 20 45 18 16}
		$bin3 = {4D 00 4D 00 43 00 00 00 67 00 75 00 69 00 64 00 56 00 47 00 41 00 00 00 5F 00 73 00 76 00 67 00}
		$inj1 = "?AVCinj2008Dlg@@" ascii
		$inj2 = "?AVCinj2008App@@" ascii

	condition:
		($mz at 0) and (( any of ($bin*)) or (3 of ($kd*)) or ( all of ($inj*)))
}
