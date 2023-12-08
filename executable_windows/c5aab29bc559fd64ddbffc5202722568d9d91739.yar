rule DoublePulsarXor_Petya
{
	meta:
		description = "Rule to hit on the XORed DoublePulsar shellcode"
		author = "Patrick Jones"
		company = "Booz Allen Hamilton"
		reference1 = "https://www.boozallen.com/s/insight/publication/the-petya-ransomware-outbreak.html"
		reference2 = "https://www.boozallen.com/content/dam/boozallen_site/sig/pdf/white-paper/rollup-of-booz-allen-petya-research.pdf"
		date = "2017-06-28"
		hash = "027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745"
		hash = "64b0b58a2c030c77fdb2b537b2fcc4af432bc55ffb36599a31d418c7c69e94b1"
		os = "windows"
		filetype = "executable"

	strings:
		$DoublePulsarXor_Petya = { FD 0C 8C 5C B8 C4 24 C5 CC CC CC 0E E8 CC 24 6B CC CC CC 0F 24 CD CC CC CC 27 5C 97 75 BA CD CC CC C3 FE }

	condition:
		$DoublePulsarXor_Petya
}
