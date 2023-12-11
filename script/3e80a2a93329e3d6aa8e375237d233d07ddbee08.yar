rule Webshell_Backdoor_PHP_Agent_r57_mod_bizzz_shell_r57
{
	meta:
		description = "Detects Webshell - rule generated from from files Backdoor.PHP.Agent.php, r57.mod-bizzz.shell.txt ..."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/nikicat/web-malware-collection"
		date = "2016-01-11"
		score = 70
		hash1 = "e46777e5f1ac1652db3ce72dd0a2475ea515b37a737fffd743126772525a47e6"
		hash2 = "f51a5c5775d9cca0b137ddb28ff3831f4f394b7af6f6a868797b0df3dcdb01ba"
		hash3 = "16b6ec4b80f404f4616e44d8c21978dcdad9f52c84d23ba27660ee8e00984ff2"
		hash4 = "59105e4623433d5bf93b9e17d72a43a40a4d8ac99e4a703f1d8851ad1276cd88"
		hash5 = "6dc417db9e07420a618d44217932ca8baf3541c08d5e68281e1be10af4280e4a"
		hash6 = "5d07fdfee2dc6d81da26f05028f79badd10dec066909932129d398627b2f4e94"
		hash7 = "1db0549066f294f814ec14ba4e9f63d88c4460d68477e5895236173df437d2b8"
		hash8 = "c6a5148c81411ec9200810619fa5eec6616800a4d76c988431c272bc8679254f"
		hash9 = "59ea6cf16ea06ff47cf0e6a398df2eaec4d329707b8c3201fc63cbf0b7c85519"
		hash10 = "0e0227a0001b38fb59fc07749e80c9d298ff0e6aca126ea8f4ea68ebc9a3661f"
		hash11 = "ef74644065925aa8d64913f5f124fe73d8d289d5f019a104bf5f56689f49ba92"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "$_POST['cmd'] = which('" ascii
		$s2 = "$blah = ex(" ascii

	condition:
		filesize <600KB and all of them
}
