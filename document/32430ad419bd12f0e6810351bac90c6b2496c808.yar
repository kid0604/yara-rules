rule RoyalRoad_code_pattern3
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
		$S1 = "4746424151515151505050500000000000584242eb0642424235353336204460606060606060606061616161616161616161616161616161"
		$RTF = "{\\rt"

	condition:
		$RTF at 0 and $S1
}
