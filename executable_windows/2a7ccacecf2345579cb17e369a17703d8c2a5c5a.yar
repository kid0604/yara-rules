rule PoS_Malware_fastpos : FastPOS POS keylogger
{
	meta:
		author = "Trend Micro, Inc."
		date = "2016-05-18"
		description = "Used to detect FastPOS keyloggger + scraper"
		reference = "http://documents.trendmicro.com/assets/fastPOS-quick-and-easy-credit-card-theft.pdf"
		sample_filetype = "exe"
		os = "windows"
		filetype = "executable"

	strings:
		$string1 = "uniqyeidclaxemain"
		$string2 = "http://%s/cdosys.php"
		$string3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
		$string4 = "\\The Hook\\Release\\The Hook.pdb" nocase

	condition:
		all of ($string*)
}
