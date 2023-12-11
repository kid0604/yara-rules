rule webshell_r57shell127_r57_iFX_r57_kartal_r57_antichat
{
	meta:
		description = "Web Shell - from files r57shell127.php, r57_iFX.php, r57_kartal.php, r57.php, antichat.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ae025c886fbe7f9ed159f49593674832"
		hash1 = "513b7be8bd0595c377283a7c87b44b2e"
		hash2 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash3 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash4 = "3f71175985848ee46cc13282fbed2269"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s6 = "$res   = @mysql_query(\"SHOW CREATE TABLE `\".$_POST['mysql_tbl'].\"`\", $d"
		$s7 = "$sql1 .= $row[1].\"\\r\\n\\r\\n\";" fullword
		$s8 = "if(!empty($_POST['dif'])&&$fp) { @fputs($fp,$sql1.$sql2); }" fullword
		$s9 = "foreach($values as $k=>$v) {$values[$k] = addslashes($v);}" fullword

	condition:
		2 of them
}
