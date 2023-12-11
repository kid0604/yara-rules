rule RoyalRoad_RTF_alt_1
{
	meta:
		description = "Detects RoyalRoad weaponized RTF documents"
		reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
		date = "2020/01/15"
		author = "nao_sec"
		score = 80
		os = "windows"
		filetype = "document"

	strings:
		$S1 = "objw2180\\objh300" ascii
		$RTF = "{\\rt"

	condition:
		$RTF at 0 and $S1
}
