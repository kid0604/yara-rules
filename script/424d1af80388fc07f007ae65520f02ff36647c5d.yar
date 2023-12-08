rule WebShell__PH_Vayv_PHVayv_PH_Vayv_alt_1
{
	meta:
		description = "PHP Webshells Github Archive - from files PH Vayv.php, PHVayv.php, PH_Vayv.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "b51962a1ffa460ec793317571fc2f46042fd13ee"
		hash1 = "408ac9ca3d435c0f78bda370b33e84ba25afc357"
		hash2 = "4003ae289e3ae036755976f8d2407c9381ff5653"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s4 = "<form method=\"POST\" action=\"<?echo \"PHVayv.php?duzkaydet=$dizin/$duzenle"
		$s12 = "<? if ($ekinci==\".\" or  $ekinci==\"..\") {" fullword
		$s17 = "name=\"duzenx2\" value=\"Klas" fullword

	condition:
		2 of them
}
