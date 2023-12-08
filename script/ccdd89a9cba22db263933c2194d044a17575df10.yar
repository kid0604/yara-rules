rule EXT_MAL_JS_SocGholish_Mar21_1 : js socgholish
{
	meta:
		description = "Triggers on SocGholish JS files"
		author = "Nils Kuhnert"
		date = "2021-03-29"
		modified = "2023-01-02"
		hash = "7ccbdcde5a9b30f8b2b866a5ca173063dec7bc92034e7cf10e3eebff017f3c23"
		hash = "f6d738baea6802cbbb3ae63b39bf65fbd641a1f0d2f0c819a8c56f677b97bed1"
		hash = "c7372ffaf831ad963c0a9348beeaadb5e814ceeb878a0cc7709473343d63a51c"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "new ActiveXObject('Scripting.FileSystemObject');" ascii
		$s2 = "['DeleteFile']" ascii
		$s3 = "['WScript']['ScriptFullName']" ascii
		$s4 = "['WScript']['Sleep'](1000)" ascii
		$s5 = "new ActiveXObject('MSXML2.XMLHTTP')" ascii
		$s6 = "this['eval']" ascii
		$s7 = "String['fromCharCode']"
		$s8 = "2), 16)," ascii
		$s9 = "= 103," ascii
		$s10 = "'00000000'" ascii

	condition:
		filesize >3KB and filesize <5KB and 8 of ($s*)
}
