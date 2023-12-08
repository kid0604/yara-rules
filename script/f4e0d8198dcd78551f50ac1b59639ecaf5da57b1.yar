rule WebShell_Gamma_Web_Shell
{
	meta:
		description = "PHP Webshells Github Archive - file Gamma Web Shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "7ef773df7a2f221468cc8f7683e1ace6b1e8139a"
		os = "linux"
		filetype = "script"

	strings:
		$s4 = "$ok_commands = ['ls', 'ls -l', 'pwd', 'uptime'];" fullword
		$s8 = "### Gamma Group <http://www.gammacenter.com>" fullword
		$s15 = "my $error = \"This command is not available in the restricted mode.\\n\";" fullword
		$s20 = "my $command = $self->query('command');" fullword

	condition:
		2 of them
}
