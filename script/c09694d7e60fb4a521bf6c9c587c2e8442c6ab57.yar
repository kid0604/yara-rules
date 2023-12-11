rule cfm_shell : webshell
{
	meta:
		description = "Laudanum Injector Tools - file shell.cfm"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "885e1783b07c73e7d47d3283be303c9719419b92"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "Executable: <Input type=\"text\" name=\"cmd\" value=\"cmd.exe\"><br>" fullword ascii
		$s2 = "<cfif ( #suppliedCode# neq secretCode )>" fullword ascii
		$s3 = "<cfif IsDefined(\"form.cmd\")>" fullword ascii

	condition:
		filesize <20KB and 2 of them
}
