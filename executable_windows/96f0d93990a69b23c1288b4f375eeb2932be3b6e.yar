import "pe"

rule APT_UNC4736_NK_MAL_TAXHAUL_3CX_Apr23_1
{
	meta:
		description = "Detects TAXHAUL (AKA TxRLoader) malware used in the 3CX compromise by UNC4736"
		author = "Mandiant"
		date = "2023-03-04"
		score = 80
		reference = "https://www.3cx.com/blog/news/mandiant-initial-results/"
		os = "windows"
		filetype = "executable"

	strings:
		$p00_0 = {410f45fe4c8d3d[4]eb??4533f64c8d3d[4]eb??4533f64c8d3d[4]eb}
		$p00_1 = {4d3926488b01400f94c6ff90[4]41b9[4]eb??8bde4885c074}

	condition:
		uint16(0)==0x5A4D and any of them
}
