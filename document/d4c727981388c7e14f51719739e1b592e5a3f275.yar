rule RoyalRoad_code_pattern1
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
		$S1 = "48905d006c9c5b0000000000030101030a0a01085a5ab844eb7112ba7856341231"
		$RTF = "{\\rt"

	condition:
		$RTF at 0 and $S1
}
