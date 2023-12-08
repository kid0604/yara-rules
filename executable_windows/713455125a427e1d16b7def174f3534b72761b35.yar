rule DoublePulsarDllInjection_Petya
{
	meta:
		description = "Rule to hit on the XORed DoublePulsar DLL injection shellcode"
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
		$DoublePulsarDllInjection_Petya = { 45 20 8D 93 8D 92 8D 91 8D 90 92 93 91 97 0F 9F 9E 9D 99 84 45 29 84 4D 20 CC CD CC CC 9B 84 45 03 84 45 14 84 45 49 CC 33 33 33 24 77 CC CC CC 84 45 49 C4 33 33 33 24 84 CD CC CC 84 45 49 DC 33 33 33 84 47 49 CC 33 33 33 84 47 41 }

	condition:
		$DoublePulsarDllInjection_Petya
}
