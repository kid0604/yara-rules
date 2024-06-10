import "pe"

rule sig_24952_Document_2023_vbs
{
	meta:
		description = "24952-files - file Document[2023.10.11_08-07].vbs"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2024/06/10/icedid-brings-screenconnect-and-csharp-streamer-to-alphv-ransomware-deployment"
		date = "2024-05-27"
		hash1 = "5bab2bc0843f9d5124b39f80e12ad6d1f02416b0340d7cfec8cf7b14cd4385bf"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "objShell.Run \"C://windows/system32/regsvr32.exe \" & quick_launch_location" fullword ascii
		$s2 = "quick_launch_location = \"C://windows/Temp/0370-1.dll\"" fullword ascii
		$s3 = "Set objShell = CreateObject( \"WScript.Shell\" )" fullword ascii
		$s4 = "E.DataType=\"bin.base64\"" fullword ascii
		$s5 = "Set E=D.createElement(\"E\")" fullword ascii
		$s6 = "Set S=CreateObject(\"ADODB.Stream\")" fullword ascii
		$s7 = "Set D=CreateObject(\"Microsoft.XMLDOM\")" fullword ascii
		$s8 = "an/|m|J|S|Z|bartZ|y|R|L|5|T|/|bartN|C|7|R|U|k|1|v|l|P|5|n|z|s|9|biboranX|5|a|+|U|/|k|f|E|2|8|1|d|8|5|T|bart+|J|e|c|2|1|r|Y|z|bar" ascii
		$s9 = "S.Write B" fullword ascii
		$s10 = "|B|A|A|A|A|T|I|0|9|o|Q|bart8|B|A|E|m|L|D|0|y|L|x|U|i|L|0|+|h|L|6|f|/|/|h|c|B|1|bartF|k|m|L|D|0|i|D|y|P|9|I|/|8|B|m|R|D|k|s|Q|X|X" ascii
		$s11 = "S|A|C|A|A|B|J|i|9|biboranh|M|Y|+|J|I|i|/|n|o|N|u|3|/|/|0|y|N|j|X|A|B|A|A|B|B|u|I|M|bartA|A|A|B|I|biboranj|V|Q|k|Y|E|i|L|y|0|y|N|" ascii
		$s12 = "|i|A|A|biboranA|A|E|i|N|B|f|G|p|A|Q|B|I|O|8|h|0|B|e|h|j|barto|P|/|/|x|w|M|B|A|A|A|A|S|I|biboranv|L|S|I|t|F|6|D|P|b|S|I|m|I|i|A|A" ascii
		$s13 = "S|I|t|c|J|D|B|I|i|8|d|I|biborang|8|Q|g|X|8|O|L|y|/|8|V|8|t|A|A|A|biboranO|j|9|7|v|/|/|z|E|i|J|X|C|Q|I|S|I|l|biboran0|J|B|B|X|S|I" ascii
		$s14 = "|D|K|D|6|Q|F|0|G|Y|P|5|A|X|V|5|R|bartY|v|P|S|I|1|N|bart0|E|y|L|x|k|G|L|1|O|i|b|+|v|/|/|6|7|x|F|i|8|9|I|j|U|3|bartQ|T|I|v|G|Q|Y|v" ascii
		$s15 = "|F|d|b|I|B|A|E|g|z|x|E|i|J|R|e|+|L|8|k|y|L|8|b|r|A|/|w|bartA|A|u|Y|A|f|A|A|B|B|i|/|l|J|i|9|j|o|t|M|biboranv|/|/|4|t|N|X|0|i|J|R|" ascii
		$s16 = "I|k|I|S|I|t|d|E|E|i|L|y|+|i|K|4|/|biboran/|/|S|I|t|V|E|I|v|I|R|I|t|C|I|E|i|L|U|biborang|j|o|p|x|k|A|A|I|l|D|E|E|i|L|R|R|C|L|U|B|" ascii
		$s17 = "O|h|v|m|A|biboranA|F|u|8|M|j|t|/|c|bartn|J|o|2|Z|G|8|5|w|B|J|G|m|d|bartv|E|c|f|y|v|V|I|C|E|Z|Y|biborank|h|4|i|R|Y|+|m|Z|l|I|K|/|" ascii
		$s18 = "|I|F|biboranV|W|V|0|F|U|Q|V|V|B|biboranV|k|F|X|S|I|2|s|J|N|D|9|/|/|9|I|g|e|w|w|A|w|A|A|S|biboranI|s|F|P|u|w|B|A|E|g|z|x|E|i|J|h|" ascii
		$s19 = "v|3|/|/|0|i|biboranL|0|4|v|P|S|I|X|bartA|d|A|j|/|F|b|Z|bartB|A|Q|D|r|B|v|8|V|5|j|8|B|A|E|i|L|X|C|Q|w|S|I|P|E|bartI|F|/|D|z|M|bar" ascii
		$s20 = "ranN|D|X|M|0|/|/|+|L|R|Y|h|M|i|U|Q|k|a|I|l|E|J|G|B|B|D|bartx|B|A|G|G|Z|I|D|3|7|A|D|x|biboranF|F|g|E|E|7|x|w|+|P|5|w|A|A|A|bibora" ascii

	condition:
		uint16(0)==0x0a0d and filesize <3000KB and 8 of them
}
