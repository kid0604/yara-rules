rule derusbi_linux
{
	meta:
		description = "Derusbi Server Linux version"
		date = "2015-12-09"
		author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
		os = "linux"
		filetype = "executable"

	strings:
		$PS1 = "PS1=RK# \\u@\\h:\\w \\$"
		$cmd = "unset LS_OPTIONS;uname -a"
		$pname = "[diskio]"
		$rkfile = "/tmp/.secure"
		$ELF = "\x7fELF"

	condition:
		$ELF at 0 and $PS1 and $cmd and $pname and $rkfile
}
