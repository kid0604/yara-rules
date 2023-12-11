rule Webshell_r57shell_2
{
	meta:
		description = "Detects Webshell R57"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "e46777e5f1ac1652db3ce72dd0a2475ea515b37a737fffd743126772525a47e6"
		hash2 = "aa957ca4154b7816093d667873cf6bdaded03f820e84d8f1cd5ad75296dd5d4d"
		hash3 = "aa957ca4154b7816093d667873cf6bdaded03f820e84d8f1cd5ad75296dd5d4d"
		hash4 = "756b788401aad4bfd4dbafd15c382d98e3ba079390addb5b0cea7ff7f985f881"
		hash5 = "756b788401aad4bfd4dbafd15c382d98e3ba079390addb5b0cea7ff7f985f881"
		hash6 = "16b6ec4b80f404f4616e44d8c21978dcdad9f52c84d23ba27660ee8e00984ff2"
		hash7 = "59105e4623433d5bf93b9e17d72a43a40a4d8ac99e4a703f1d8851ad1276cd88"
		hash8 = "1db0549066f294f814ec14ba4e9f63d88c4460d68477e5895236173df437d2b8"
		hash9 = "c6a5148c81411ec9200810619fa5eec6616800a4d76c988431c272bc8679254f"
		hash10 = "c6a5148c81411ec9200810619fa5eec6616800a4d76c988431c272bc8679254f"
		hash11 = "59ea6cf16ea06ff47cf0e6a398df2eaec4d329707b8c3201fc63cbf0b7c85519"
		hash12 = "0e0227a0001b38fb59fc07749e80c9d298ff0e6aca126ea8f4ea68ebc9a3661f"
		hash13 = "ef74644065925aa8d64913f5f124fe73d8d289d5f019a104bf5f56689f49ba92"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "$connection = @ftp_connect($ftp_server,$ftp_port,10);" fullword ascii
		$s2 = "echo $lang[$language.'_text98'].$suc.\"\\r\\n\";" fullword ascii

	condition:
		filesize <900KB and all of them
}
