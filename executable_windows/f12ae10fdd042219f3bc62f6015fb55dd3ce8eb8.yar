import "pe"

rule APT_Lazarus_RAT_Jun18_1
{
	meta:
		description = "Detects Lazarus Group RAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/DrunkBinary/status/1002587521073721346"
		date = "2018-06-01"
		hash1 = "c10363059c57c52501c01f85e3bb43533ccc639f0ea57f43bae5736a8e7a9bc8"
		hash2 = "e98991cdd9ddd30adf490673c67a4f8241993f26810da09b52d8748c6160a292"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "www.marmarademo.com/include/extend.php" fullword ascii
		$a2 = "www.33cow.com/include/control.php" fullword ascii
		$a3 = "www.97nb.net/include/arc.sglistview.php" fullword ascii
		$c1 = "Content-Disposition: form-data; name=\"file1\"; filename=\"example.dat\"" fullword ascii
		$c2 = "Content-Disposition: form-data; name=\"file1\"; filename=\"pratice.pdf\"" fullword ascii
		$c3 = "Content-Disposition: form-data; name=\"file1\"; filename=\"happy.pdf\"" fullword ascii
		$c4 = "Content-Disposition: form-data; name=\"file1\"; filename=\"my.doc\"" fullword ascii
		$c5 = "Content-Disposition: form-data; name=\"board_id\"" fullword ascii
		$s1 = "Winhttp.dll" fullword ascii
		$s2 = "Wsock32.dll" fullword ascii
		$s3 = "WM*.tmp" fullword ascii
		$s4 = "FM*.tmp" fullword ascii
		$s5 = "Cache-Control: max-age=0" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and (1 of ($a*) or 2 of ($c*) or 4 of them )
}
