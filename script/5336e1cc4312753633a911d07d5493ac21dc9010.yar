rule WebShell_hiddens_shell_v1
{
	meta:
		description = "PHP Webshells Github Archive - file hiddens shell v1.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1674bd40eb98b48427c547bf9143aa7fbe2f4a59"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<?$d='G7mHWQ9vvXiL/QX2oZ2VTDpo6g3FYAa6X+8DMIzcD0eHZaBZH7jFpZzUz7XNenxSYvBP2Wy36U"

	condition:
		all of them
}
