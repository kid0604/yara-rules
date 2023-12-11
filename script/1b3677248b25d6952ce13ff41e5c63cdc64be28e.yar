rule WebShell_STNC_WebShell_v0_8
{
	meta:
		description = "PHP Webshells Github Archive - file STNC WebShell v0.8.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "52068c9dff65f1caae8f4c60d0225708612bb8bc"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s3 = "if(isset($_POST[\"action\"])) $action = $_POST[\"action\"];" fullword
		$s8 = "elseif(fe(\"system\")){ob_start();system($s);$r=ob_get_contents();ob_end_clean()"
		$s13 = "{ $pwd = $_POST[\"pwd\"]; $type = filetype($pwd); if($type === \"dir\")chdir($pw"

	condition:
		2 of them
}
