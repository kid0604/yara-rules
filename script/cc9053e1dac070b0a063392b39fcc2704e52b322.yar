rule webshell_asp_dabao
{
	meta:
		description = "Web Shell - file dabao.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "3919b959e3fa7e86d52c2b0a91588d5d"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = " Echo \"<input type=button name=Submit onclick=\"\"document.location =&#039;\" &"
		$s8 = " Echo \"document.Frm_Pack.FileName.value=\"\"\"\"+year+\"\"-\"\"+(month+1)+\"\"-"

	condition:
		all of them
}
