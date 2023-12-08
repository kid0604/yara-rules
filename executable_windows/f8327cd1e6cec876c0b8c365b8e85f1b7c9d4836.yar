rule Duqu2_UAs
{
	meta:
		description = "Detects Duqu2 Executable based on the specific UAs in the file"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/70504/the-mystery-of-duqu-2-0-a-sophisticated-cyberespionage-actor-returns/"
		date = "2016-07-02"
		score = 80
		hash1 = "52fe506928b0262f10de31e783af8540b6a0b232b15749d647847488acd0e17a"
		hash2 = "81cdbe905392155a1ba8b687a02e65d611b60aac938e470a76ef518e8cffd74d"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Mozilla/5.0 (Windows NT 6.1; U; ru; rv:5.0.1.6) Gecko/20110501 Firefox/5.0.1 Firefox/5.0.1" fullword wide
		$x2 = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.63 Safari/535.7xs5D9rRDFpg2g" fullword wide
		$x3 = "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1; FDM; .NET CLR 1.1.4322)" fullword wide
		$x4 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0a2) Gecko/20110612 Firefox/6.0a2" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <800KB and all of them )
}
