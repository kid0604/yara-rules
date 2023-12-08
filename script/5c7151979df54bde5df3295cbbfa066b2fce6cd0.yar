rule WebShell_Moroccan_Spamers_Ma_EditioN_By_GhOsT
{
	meta:
		description = "PHP Webshells Github Archive - file Moroccan Spamers Ma-EditioN By GhOsT.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "31e5473920a2cc445d246bc5820037d8fe383201"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s4 = "$content = chunk_split(base64_encode($content)); " fullword
		$s12 = "print \"Sending mail to $to....... \"; " fullword
		$s16 = "if (!$from && !$subject && !$message && !$emaillist){ " fullword

	condition:
		all of them
}
