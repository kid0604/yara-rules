rule Molerats_Jul17_Sample_4
{
	meta:
		description = "Detects Molerats sample - July 2017"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
		date = "2017-07-07"
		hash1 = "512a14130a7a8b5c2548aa488055051ab7e725106ddf2c705f6eb4cfa5dc795c"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "get-itemproperty -path 'HKCU:\\SOFTWARE\\Microsoft\\' -name 'KeyName')" wide
		$x2 = "O.Run C & chrw(34) & \"[System.IO.File]::" wide
		$x3 = "HKCU\\SOFTWARE\\Microsoft\\\\KeyName\"" fullword wide

	condition:
		( filesize <700KB and 1 of them )
}
