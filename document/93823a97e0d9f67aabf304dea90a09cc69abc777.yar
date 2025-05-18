rule Brooxml_Hunting
{
	meta:
		description = "Detects Microsoft OOXML files with prepended data/manipulated header"
		author = "Proofpoint"
		category = "hunting"
		date = "2024-11-27"
		score = 70
		reference = "https://x.com/threatinsight/status/1861817946508763480"
		id = "1ffea1c7-9f97-5bb1-93d7-ce914765416f"
		os = "windows,linux,macos"
		filetype = "document"

	strings:
		$pk_ooxml_magic = {50 4b 03 04 [22] 13 00 [2] 5b 43 6f 6e 74 65 6e 74 5f 54 79 70 65 73 5d 2e 78 6d 6c}
		$pk_0102 = {50 4b 01 02}
		$pk_0304 = {50 4b 03 04}
		$pk_0506 = {50 4b 05 06}
		$pk_0708 = {50 4b 07 08}
		$word = "word/"
		$ole = {d0 cf 11 e0}
		$mz = {4d 5a}
		$tef = {78 9f 3e 22}

	condition:
		$pk_ooxml_magic in (4..16384) and $pk_0506 in (16384.. filesize ) and #pk_0506==1 and #pk_0102>2 and #pk_0304>2 and $word and not ($pk_0102 at 0) and not ($pk_0304 at 0) and not ($pk_0506 at 0) and not ($pk_0708 at 0) and not ($ole at 0) and not ($mz at 0) and not ($tef at 0)
}
