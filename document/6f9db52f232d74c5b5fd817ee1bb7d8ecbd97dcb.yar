rule Exp_EPS_CVE20152545
{
	meta:
		description = "Detects EPS Word Exploit CVE-2015-2545"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research - ME"
		date = "2017-07-19"
		score = 70
		os = "windows"
		filetype = "document"

	strings:
		$s1 = "word/media/image1.eps" ascii
		$s2 = "-la;7(la+" ascii

	condition:
		uint16(0)==0x4b50 and ($s1 and #s2>20)
}
