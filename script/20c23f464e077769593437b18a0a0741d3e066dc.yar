rule WebShell_php_webshells_aspydrv
{
	meta:
		description = "PHP Webshells Github Archive - file aspydrv.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3d8996b625025dc549d73cdb3e5fa678ab35d32a"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "Target = \"D:\\hshome\\masterhr\\masterhr.com\\\"  ' ---Directory to which files"
		$s1 = "nPos = InstrB(nPosEnd, biData, CByteString(\"Content-Type:\"))" fullword
		$s3 = "Document.frmSQL.mPage.value = Document.frmSQL.mPage.value - 1" fullword
		$s17 = "If request.querystring(\"getDRVs\")=\"@\" then" fullword
		$s20 = "' ---Copy Too Folder routine Start" fullword

	condition:
		3 of them
}
