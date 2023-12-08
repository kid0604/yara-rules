rule pos_jack
{
	meta:
		author = "@patrickrolsen"
		maltype = "Point of Sale (POS) Malware"
		version = "0.1"
		reference = "http://blog.spiderlabs.com/2014/02/jackpos-the-house-always-wins.html"
		date = "2/22/2014"
		description = "Detects Point of Sale (POS) malware known as JackPOS"
		os = "windows"
		filetype = "executable"

	strings:
		$pdb1 = "\\ziedpirate.ziedpirate-PC\\"
		$pdb2 = "\\sop\\sop\\"

	condition:
		uint16(0)==0x5A4D and 1 of ($pdb*)
}
