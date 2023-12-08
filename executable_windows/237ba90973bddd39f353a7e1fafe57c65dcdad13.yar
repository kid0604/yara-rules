rule HDRoot_Sample_Jul17_2
{
	meta:
		description = "Detects HDRoot samples"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Winnti HDRoot VT"
		date = "2017-07-07"
		super_rule = 1
		hash1 = "1c302ed9786fc600073cc6f3ed2e50e7c23785c94a2908f74f92971d978b704b"
		hash2 = "3b7cfa40e26fb6b079b55ec030aba244a6429e263a3d9832e32ab09e7a3c4a9c"
		hash3 = "71eddf71a94c5fd04c9f3ff0ca1eb6b1770df1a3a8f29689fb8588427b5c9e8e"
		hash4 = "80e088f2fd2dbde0f9bc21e056b6521991929c4e0ecd3eb5833edff6362283f4"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "http://microsoftcompanywork.htm" fullword ascii
		$x2 = "compose.aspx?s=%4X%4X%4X%4X%4X%4X" fullword ascii
		$t1 = "http://babelfish.yahoo.com/translate_url?" fullword ascii
		$t2 = "http://translate.google.com/translate?prev=hp&hl=en&js=n&u=%s?%d&sl=es&tl=en" fullword ascii
		$u1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; SLCC1; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.5." ascii
		$u2 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Maxthon)" fullword ascii
		$u3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Maxthon; TERA:" fullword ascii
		$s1 = "\\system32\\ntoskrnl.exe" ascii
		$s2 = "Schedsvc.dll" fullword wide
		$s3 = "dllserver64.dll" fullword ascii
		$s4 = "C:\\TERA_SR.txt" fullword ascii
		$s5 = "updatevnsc.dat" fullword wide
		$s6 = "tera dll service global event" fullword ascii
		$s7 = "Referer: http://%s/%s" fullword ascii
		$s8 = "tera replace dll config" fullword ascii
		$s9 = "SetupDll64.dll" fullword ascii
		$s10 = "copy %%ComSpec%% \"%s\"" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and (1 of ($x*) or all of ($u*) or 8 of them )
}
