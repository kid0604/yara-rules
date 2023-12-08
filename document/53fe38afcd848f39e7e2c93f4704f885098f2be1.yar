rule RoyalRoad_code_pattern2
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
		$S1 = "653037396132353234666136336135356662636665" ascii
		$RTF = "{\\rt"

	condition:
		$RTF at 0 and $S1
}
