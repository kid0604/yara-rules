rule webshell_aZRaiLPhp_v1_0
{
	meta:
		description = "Web Shell - file aZRaiLPhp v1.0.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "26b2d3943395682e36da06ed493a3715"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s5 = "echo \" <font color='#0000FF'>CHMODU \".substr(base_convert(@fileperms($"
		$s7 = "echo \"<a href='./$this_file?op=efp&fname=$path/$file&dismi=$file&yol=$path'><fo"

	condition:
		all of them
}
