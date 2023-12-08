rule WebShell_SimAttacker___Vrsion_1_0_0___priv8_4_My_friend
{
	meta:
		description = "PHP Webshells Github Archive - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "6454cc5ab73143d72cf0025a81bd1fe710351b44"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s4 = "&nbsp;Iranian Hackers : WWW.SIMORGH-EV.COM <br>" fullword
		$s5 = "//fake mail = Use victim server 4 DOS - fake mail " fullword
		$s10 = "<a style=\"TEXT-DECORATION: none\" href=\"http://www.simorgh-ev.com\">" fullword
		$s16 = "error_reporting(E_ERROR | E_WARNING | E_PARSE);" fullword
		$s17 = "echo \"<font size='1' color='#999999'>Dont in windows\";" fullword
		$s19 = "$Comments=$_POST['Comments'];" fullword
		$s20 = "Victim Mail :<br><input type='text' name='to' ><br>" fullword

	condition:
		3 of them
}
