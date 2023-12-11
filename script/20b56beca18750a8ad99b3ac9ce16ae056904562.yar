rule Webshell_zehir
{
	meta:
		description = "Detects Webshell - rule generated from from files elmaliseker.asp, zehir.asp, zehir.txt, zehir4.asp, zehir4.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "16e1e886576d0c70af0f96e3ccedfd2e72b8b7640f817c08a82b95ff5d4b1218"
		hash2 = "0c5f8a2ed62d10986a2dd39f52886c0900a18c03d6d279207b8de8e2ed14adf6"
		hash3 = "cb9d5427a83a0fc887e49f07f20849985bd2c3850f272ae1e059a08ac411ff66"
		hash4 = "b57bf397984545f419045391b56dcaf7b0bed8b6ee331b5c46cee35c92ffa13d"
		hash5 = "febf37a9e8ba8ece863f506ae32ad398115106cc849a9954cbc0277474cdba5c"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "for (i=1; i<=frmUpload.max.value; i++) str+='File '+i+': <input type=file name=file'+i+'><br>';" fullword ascii
		$s2 = "if (frmUpload.max.value<=0) frmUpload.max.value=1;" fullword ascii

	condition:
		filesize <200KB and 1 of them
}
