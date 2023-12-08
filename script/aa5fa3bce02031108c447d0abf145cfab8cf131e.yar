rule WEBSHELL_PAS_webshell_PerlNetworkScript
{
	meta:
		author = "FR/ANSSI/SDO"
		description = "Detects PERL scripts created by P.A.S. webshell"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		date = "2021-02-15"
		score = 90
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$pl_start = "#!/usr/bin/perl\n$SIG{'CHLD'}='IGNORE'; use IO::Socket; use FileHandle;"
		$pl_status = "$o=\" [OK]\";$e=\" Error: \""
		$pl_socket = "socket(SOCKET, PF_INET, SOCK_STREAM,$tcp) or die print \"$l$e$!$l"
		$msg1 = "print \"$l OK! I\\'m successful connected.$l\""
		$msg2 = "print \"$l OK! I\\'m accept connection.$l\""

	condition:
		filesize <6000 and ($pl_start at 0 and all of ($pl*)) or any of ($msg*)
}
