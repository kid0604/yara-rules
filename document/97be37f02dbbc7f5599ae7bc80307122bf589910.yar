rule GoldenEye_Ransomware_XLS
{
	meta:
		description = "GoldenEye XLS with Macro - file Schneider-Bewerbung.xls"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/jp2SkT"
		date = "2016-12-06"
		hash1 = "2320d4232ee80cc90bacd768ba52374a21d0773c39895b88cdcaa7782e16c441"
		os = "windows"
		filetype = "document"

	strings:
		$x1 = "fso.GetTempName();tmp_path = tmp_path.replace('.tmp', '.exe')" fullword ascii
		$x2 = "var shell = new ActiveXObject('WScript.Shell');shell.run(t'" fullword ascii

	condition:
		( uint16(0)==0xcfd0 and filesize <4000KB and 1 of them )
}
