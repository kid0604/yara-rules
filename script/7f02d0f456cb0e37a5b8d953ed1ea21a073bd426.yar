import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_JS_LocalPersistence
{
	meta:
		author = "ditekSHen"
		description = "Detects JavaScript files used for persistence and executable or script execution"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "ActiveXObject" ascii
		$s2 = "Shell.Application" ascii
		$s3 = "ShellExecute" ascii
		$ext1 = ".exe" ascii
		$ext2 = ".ps1" ascii
		$ext3 = ".lnk" ascii
		$ext4 = ".hta" ascii
		$ext5 = ".dll" ascii
		$ext6 = ".vb" ascii
		$ext7 = ".com" ascii
		$ext8 = ".js" ascii
		$action = "\"Open\"" ascii

	condition:
		$action and 2 of ($s*) and 1 of ($ext*) and filesize <500KB
}
